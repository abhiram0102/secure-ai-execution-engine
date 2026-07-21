import sys
import json
import traceback

sys.path.append("/sandbox")

def main():
    try:
        # Import the user's pure python code
        # pyrefly: ignore [missing-import]
        import ai_code_sandbox as code
        
        # Read the JSON RPC request
        with open("/sandbox/request.json", "r") as f:
            request = json.load(f)
            
        func_name = request['function']
        args = request.get('args', [])
        kwargs = request.get('kwargs', {})
        
        # Execute the function (with or without a class instance)
        if 'class_name' in request and request['class_name']:
            cls = getattr(code, request['class_name'])
            init_args = request.get('init_args', [])
            init_kwargs = request.get('init_kwargs', {})
            instance = cls(*init_args, **init_kwargs)
            func = getattr(instance, func_name)
        else:
            func = getattr(code, func_name)
            
        result = func(*args, **kwargs)
        
        # Transport the result back to the C-Harness
        print(f"__RESULT__:{json.dumps(result)}")
        
    except Exception as e:
        # If there's an error, print it so the C-Harness can capture it in stderr
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
