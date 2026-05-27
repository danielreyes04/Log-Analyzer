from src.parser import parse_log
import pandas as pd
# diferentes df para probar cada columna que genera el parser
path_accepted_password = 'test/fixtures/accepted_password.log'
df_prueba_accepted_password = parse_log(path_accepted_password)

path_userad = 'test/fixtures/useradd.log'
df_userad = parse_log(path_userad)

path_usermod = 'test/fixtures/usermod.log'
df_usermod = parse_log(path_usermod)

path_command = 'test/fixtures/command.log'
df_command = parse_log(path_command)


#pruebas para cada columna con pytest
def test_parser_ip():
    ip = df_prueba_accepted_password.loc[0,'ip_origin']
    assert ip == '203.101.190.9'

def test_service():
    service = df_prueba_accepted_password.loc[0,'service']
    assert service == 'sshd'

def test_fecha():
    fecha = df_prueba_accepted_password.loc[0,'fecha_hora']
    assert fecha == 'Mar  6 06:19:54'

def test_host():
    host = df_prueba_accepted_password.loc[0,'host']
    assert host == '172-31-35-28'

def message_type():
    message = df_prueba_accepted_password.loc[0,'message_type']
    assert message in ['Accepted password','Invalid user','Received disconnect']

def test_user():
    user= df_prueba_accepted_password.loc[0,'user']
    assert user == 'root'

def test_port():
    port= df_prueba_accepted_password.loc[0,'port']
    assert port == '42825'


def test_pid():
    pid= df_prueba_accepted_password.loc[0,'pid']
    assert pid == '1465'

def test_uid():
    uid =df_userad.loc[0,'UID'] 
    assert uid == '1002'

def test_gid():
    gid = df_userad['GID'].iloc[0]
    assert gid == '1002'

def test_group_name():
    group = df_usermod.loc[0,'group_name']
    assert group == 'sudo'

def test_command():
    command = df_command.loc[0,'command']
    assert command == 'cat /etc/shadow'