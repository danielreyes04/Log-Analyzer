from src.alert import *
from src.detector import *
from src.parser import parse_log
import click


@click.command() # para convertir la funcion en un comando CLI
@click.option('--log', default='data/raw/auth.log', help='Ruta del archivo de log') # se agreaga una opcion
def main (log):
    df = parse_log(log)

    df_brute_force = brute_force(df)
    df_user_enumeration = user_enumeration(df)
    df_successful_intrusion = successful_intrusion(df)
    df_privilage_escalation = privilage_escalation(df)

    alert_brute_force(df_brute_force)
    alert_user_enumeration(df_user_enumeration)
    alert_privilage_escalation(df_privilage_escalation)
    alert_successful_intrusion(df_successful_intrusion)


if __name__ == '__main__':
    main()