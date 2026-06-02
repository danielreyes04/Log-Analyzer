from src.parser import parse_log
from src.detector import *
import pandas as pd


df = parse_log('test/fixtures/test.log')
df_privilage_escalation = parse_log('test/fixtures/privilage_escalation.log')

def test_brute_force():
    df_brute_force = brute_force(df)
    
    assert df_brute_force.loc[0,'ip_origin'] == '65.2.161.68' 

def test_user_enumeration():
    df_user_enumeration = user_enumeration(df)
    #parar decirle que si encontro algun usuario como admin
    assert (df_user_enumeration['user'] == 'admin').any()

def test_successful_intrusion():
    df_successful_intrusion = successful_intrusion(df)
    # se hace asi la condicion porque la ip que retorna la funcion de intrucion esta como index
    assert '65.2.161.68' in df_successful_intrusion.index

def test_privilage_escalation():
    df_privilage = privilage_escalation(df_privilage_escalation)
    assert ((df_privilage['service'] =='usermod') | (df_privilage_escalation['service'] =='sudo')).any()