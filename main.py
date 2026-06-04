from src.alert import *
from src.detector import *
from src.parser import parse_log

#ruta del archivo a analizar
path = 'data/raw/auth.log'
# Parser para crear el df
df = parse_log(path)

df_brute_force = brute_force(df)
df_user_enumeration = user_enumeration(df)
df_successful_intrusion = successful_intrusion(df)
df_privilage_escalation = privilage_escalation(df)

print(alert_brute_force(df_brute_force))
print(df['fecha_hora'])