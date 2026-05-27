from src.detector import *
from src.parser import parse_log

path = '/test/fixtures/test.log'
df = parse_log(path)
test = brute_force(df)
print(test)