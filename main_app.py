import os
import json
import ast

try:
    import supervisor
except ImportError:
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), 'advanced-sandbox'))
    import supervisor

AI_CODE_FILE = "ai_code.py"

class ClassProxy:
    def __init__(self, sandbox, class_name, *init_args, **init_kwargs):
        self.sandbox = sandbox
        self.class_name = class_name
        self.init_args = init_args
        self.init_kwargs = init_kwargs
        
    def __getattr__(self, method_name):
        def rpc_call(*args, **kwargs):
            return self.sandbox._execute_rpc({
                "class_name": self.class_name,
                "init_args": self.init_args,
                "init_kwargs": self.init_kwargs,
                "function": method_name,
                "args": args,
                "kwargs": kwargs
            }, f"{self.class_name}.{method_name}")
        return rpc_call

class UniversalSandbox:
    """A completely universal proxy that can run ANY function or instantiate ANY class inside the sandbox."""
    def __init__(self, ai_code_str, extra_mounts=None):
        self._ai_code_str = ai_code_str
        self._extra_mounts = extra_mounts or {}

    def use_class(self, class_name, *init_args, **init_kwargs):
        """Returns a Stateful proxy object that reconstructs the class on every call."""
        return ClassProxy(self, class_name, *init_args, **init_kwargs)

    def _execute_rpc(self, request_dict, print_name):
        print(f"--> [RPC] Executing '{print_name}()' inside Sandbox...")
        
        rpc_request = json.dumps(request_dict)
        
        # Direct python call to supervisor! ZERO HTTP Latency.
        raw_response = supervisor.handle_request(
            code=self._ai_code_str,
            rpc_request=rpc_request,
            timeout_ms=5000, 
            max_out_bytes=1024*1024,
            extra_mounts=self._extra_mounts
        )
        
        sandbox_result = json.loads(raw_response.decode())
        
        if "error" in sandbox_result and sandbox_result["error"]:
            raise RuntimeError(f"Sandbox RPC Error: {sandbox_result['error']}")
            
        if sandbox_result.get("exit_code") != 0:
            raise RuntimeError(f"Sandbox execution failed: {sandbox_result.get('stderr')}")
            
        final_output = sandbox_result.get("result")
        if not final_output:
            return None
            
        try:
            if isinstance(final_output, str):
                final_output = ast.literal_eval(final_output)
        except Exception as e:
            pass
            
        return final_output

    def __getattr__(self, function_name):
        def rpc_call(*args, **kwargs):
            return self._execute_rpc({
                "function": function_name,
                "args": args,
                "kwargs": kwargs
            }, function_name)
        return rpc_call

def main():
    if not os.path.exists(AI_CODE_FILE):
        print(f"Error: {AI_CODE_FILE} not found.")
        return

    print(f"Reading AI code from {AI_CODE_FILE}...")
    with open(AI_CODE_FILE, 'r') as f:
        ai_code_str = f.read()

    print("\nInstantiating Universal Sandbox...")
    sandbox = UniversalSandbox(ai_code_str)
    
    print("\n=== RUNNING STATISTICAL CLASS ===")
    data = [12, 45, 67, 89, 34, 23, 90, 11]
    print(f"Data set: {data}")
    
    # We instantiate the class via our Reconstructive Proxy!
    analyzer = sandbox.use_class("StatisticsAnalyzer", data)
    
    mean = analyzer.calculate_mean()
    print(f"Mean: {mean}")
    
    variance = analyzer.calculate_variance()
    print(f"Variance: {variance}")
    
    print("\n=== RUNNING STANDALONE FUNCTIONS ===")
    print("Finding all prime numbers up to 100...")
    primes = sandbox.find_primes(100)
    print(f"Primes: {primes}")

if __name__ == "__main__":
    main()
