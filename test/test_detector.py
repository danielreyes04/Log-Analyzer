from src.detector import brute_force
from src.parser import parse_log

path = '/test/fixtures/test.log'
df = parse_log(path)
test = brute_force(df)