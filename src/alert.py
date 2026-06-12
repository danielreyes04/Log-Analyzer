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
    if df.empty:
        console.print('No se detecto ataque de intrusion exitosa')
    else:
        console.print("[bold red]ALERTA[/bold red]")
        console.print('Se ha detectado un posible ataque de [bold red]intrusion exitosa[/bold red]')
        for index,intrusion in df.iterrows():
            console.print(index+1) # para imprimir el numero de alerta
            #imprime la ip del dataframe con su numero de intentos fallidos por contrasña, usuario y al final el exitoso
            console.print(f'La ip {intrusion["ip_origin"]} ha tenido acceso exitoso')
            console.print(f'Con los siguientes intentos con usuario incorrecto y contraseña incorrecta: {intrusion["Failed password for invalid user"]}, contraseña incorrecta con {intrusion["Failed password"]} intentos y finalmente tuvo {intrusion["Accepted password"]} contraseñas correctas')

def alert_privilage_escalation(df):
    df_user = df.groupby('user')
    console.print("[bold red]ALERTA[/bold red]")
    console.print('Se ha detectado un posible ataque de [bold red]escala de privilegios[/bold red]')
    for user, group in df_user:
        services = group['service'].unique()
        group_name = group['group_name'].dropna().unique()
        command = group['command'].dropna().unique()
        message_type = group['message_type'].dropna().unique()

        console.print(f'El usuario {user} ha escalado privilegios en el sistema')
        console.print(f'Ha utilizado los siguientes servicios: {", ".join(services)}')
        console.print(f'Ha pertenecido a los siguientes grupos: {", ".join(group_name)}')
        console.print(f'Ha ejecutado los siguientes comandos: {", ".join(command)}')
        console.print(f'Los mensajes asociados a esta actividad son: {", ".join(message_type)}')