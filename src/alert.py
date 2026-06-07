from rich.console import Console
from src.detector import *

console = Console() # Se crea el objeto consol para imprimir por consola

def alert_brute_force(df):
    
    if df.empty:
        console.print('No se detecto ataque de fuerza bruta')
    else:

        console.print("[bold red]ALERTA[/bold red]")
        console.print('Se ha detectado un posible ataque de [bold red]fuerza bruta[/bold red]')
        # se crea el groupby para poder recorrer el df por cada ip
        df_ip= df.groupby('ip_origin')
        
        for ip,gruop in df_ip:
            #ip es la propia ip y gruop es el df filtrado solo para esa ip
            ip_print = ip
            gruop = gruop[(gruop['message_type'] == 'Failed password for invalid user')|(gruop['message_type'] == 'Failed password')]
            attempts = gruop.shape
            date = gruop['fecha_hora'].max() - gruop['fecha_hora'].min()
            # formato para sacar hora,minuto y segundo de date
            total_seconds = date.seconds
            horas = total_seconds // 3600
            minutos = (total_seconds % 3600) // 60
            segundos = total_seconds % 60
            console.print(f'La ip {ip_print} ha realizado [bold blue]{attempts[0]}[/ bold blue] intentos en el rango de {horas} horas {minutos} minutos con {segundos} segundos')    
    
    
    
def alert_user_enumeration(df):
    df_ip_user = df.groupby('ip_origin')['user'].unique() # se agrupa por ip y se obtiene los usuarios unicos por cada ip
    if df_ip_user.empty:
        console.print('No se detecto ataque de enumeracion de usuarios')
    else:
        console.print("[bold red]ALERTA[/bold red]")
        console.print('Se ha detectado un posible ataque de [bold red]enumeracion de usuarios[/bold red]')
        for ip, user in df_ip_user.items():
            users = ''
            users += ', '.join(user)  # para imprimir los usuarios separados por coma
            console.print(f'La ip {ip} ha intentado acceder con los siguientes usuarios: {users}')

    
def alert_successful_intrusion(df):
    
    pass
def privilage_escalation(df):
    
    pass
