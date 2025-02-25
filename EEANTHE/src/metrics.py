# performance_metrics.py

import tracemalloc
import time

def measure_performance(func, *args, **kwargs):
    """
    Measures the performance of an encryption or decryption function.
    
    Args:
        func: The function to measure (encryption or decryption).
        *args, **kwargs: Arguments to pass to the function.
    
    Returns:
        Tuple of (function result, performance metrics).
    """
    # Start performance measurement
    tracemalloc.start()
    start_time = time.perf_counter()

    # Execute the actual function (encryption/decryption)
    result = func(*args, **kwargs)

    # Stop performance measurement
    end_time = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Calculate performance metrics
    data_size = len(result.encode()) if isinstance(result, str) else len(result) if result else 0
    elapsed_time = end_time - start_time
    throughput = data_size / elapsed_time if elapsed_time > 0 else 0

    metrics = {
        "latency": elapsed_time,
        "throughput": throughput,
        "memory_usage": {"current": current, "peak": peak}
    }

    print("Performance Metrics:", metrics)
    return result, metrics
