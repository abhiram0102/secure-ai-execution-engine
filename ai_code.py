def add_numbers(a, b):
    return a + b

class StatisticsAnalyzer:
    def __init__(self, data):
        self.data = data
        
    def calculate_mean(self):
        if not self.data:
            return 0
        return sum(self.data) / len(self.data)

    def calculate_variance(self):
        if not self.data:
            return 0
        mean = self.calculate_mean()
        return sum((x - mean) ** 2 for x in self.data) / len(self.data)
    
def find_primes(limit):
    """Finds all prime numbers up to the limit."""
    primes = []
    for num in range(2, limit + 1):
        is_prime = True
        for i in range(2, int(num ** 0.5) + 1):
            if num % i == 0:
                is_prime = False
                break
        if is_prime:
            primes.append(num)
    return primes
