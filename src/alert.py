from rich.console import Console
from src.detector import *

console = Console() # Se crea el objeto consol para imprimir por consola

def alert_brute_force(df):
    console.print("[bold red]ALERTA[/bold red]")
    console.print('Se ha detectado un ataque de [bold red]fuerza bruta[/bold red]')
    # se crea el groupby para poder recorrer el df por cada ip
    df_ip= df.groupby('ip_origin')
    
    for ip,gruop in df_ip:
        #ip es la propia ip y gruop es el df filtrado solo para esa ip
        ip_print = ip
        attempts = gruop.shape
        console.print(f'La ip {ip_print} ha realizado [blod blue]{attempts[0]}[/ blod blue] intentos')    
    
    
    
def alert_user_enumeration(df):
    
    pass
def alert_successful_intrusion(df):
    
    pass
def privilage_escalation(df):
    
    pass
#console.print("[bold red]ALERTA[/bold red] Fuerza bruta detectada")