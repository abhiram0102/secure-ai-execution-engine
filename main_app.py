import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "advanced-sandbox"))
import supervisor

_TIMEOUT_MS    = int(os.environ.get("SANDBOX_TIMEOUT_SEC",      "30"))  * 1000
_MAX_OUT_BYTES = int(os.environ.get("SANDBOX_MAX_OUTPUT_BYTES", str(10 * 1024 * 1024)))


class ClassProxy:
    """Proxies method calls on a named class into the sandbox."""

    def __init__(self, sandbox, class_name, *init_args, **init_kwargs):
        self.sandbox      = sandbox
        self.class_name   = class_name
        self.init_args    = init_args
        self.init_kwargs  = init_kwargs

    def __getattr__(self, method_name):
        if method_name.startswith('__'):
            raise AttributeError(method_name)
        def rpc_call(*args, **kwargs):
            return self.sandbox._execute_rpc({
                "class_name":  self.class_name,
                "init_args":   self.init_args,
                "init_kwargs": self.init_kwargs,
                "function":    method_name,
                "args":        args,
                "kwargs":      kwargs,
            })
        return rpc_call


class UniversalSandbox:
    """Runs any function or class method inside the sandbox."""

    def __init__(self, ai_code_str: str, policy_json_str: str = None):
        self._ai_code_str    = ai_code_str
        self._policy_json_str = policy_json_str

    def use_class(self, class_name, *init_args, **init_kwargs) -> ClassProxy:
        return ClassProxy(self, class_name, *init_args, **init_kwargs)

    def _execute_rpc(self, request_dict: dict):
        rpc_request = json.dumps(request_dict)
        raw_response = supervisor.handle_request(
            code=self._ai_code_str,
            rpc_request=rpc_request,
            timeout_ms=_TIMEOUT_MS,
            max_out_bytes=_MAX_OUT_BYTES,
            dynamic_policy_json=self._policy_json_str,
        )
        result = json.loads(raw_response.decode())

        if result.get("error"):
            raise RuntimeError(f"Sandbox error: {result['error']}")
        if result.get("exit_code", 0) != 0:
            raise RuntimeError(f"Sandbox execution failed: {result.get('stderr')}")

        raw = result.get("result")
        if raw is None:
            return None

        # Result is json.dumps() output from dispatcher — parse it back
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw

    def __getattr__(self, function_name):
        if function_name.startswith('__'):
            raise AttributeError(function_name)
        def rpc_call(*args, **kwargs):
            return self._execute_rpc({
                "function": function_name,
                "args":     args,
                "kwargs":   kwargs,
            })
        return rpc_call
