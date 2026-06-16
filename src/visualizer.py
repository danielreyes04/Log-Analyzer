import matplotlib.pyplot as plt
import seaborn as sns

def histogram (df,column, name):
    plt.figure(figsize=(12, 6))
    sns.histplot(data = df, x = column,bins = 20)
    # para una correcta visualizacion de la grafica
    plt.xticks(rotation=45)
    plt.title(name)
    plt.savefig(f'reports/figures/{name}.png')
    plt.close()

def plot_atack_time_line(df):
    
    
    #filtramos por los 3 tipos de mensajes
    df_failed_user = df[df['message_type'] == 'Failed password for invalid user']
    df_failed = df[df['message_type'] == 'Failed password']
    df_accepted = df[df['message_type'] == 'Accepted password']

    histogram(df_failed,'date','Failed password')
    histogram(df_failed_user,'date','Failed password for user')
    histogram(df_accepted,'date','Accepted password')

def top_ip (df):
    sns.countplot(df,x = 'ip_origin')
    plt.title('top ip')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('reports/figures/top_ip.png')
    plt.close()

def top_user(df):
    # filtramos para mostrar usuarios de ssh
    df = df[df['service'] == 'sshd']

    sns.countplot(df,x = 'user')
    plt.title('top users')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('reports/figures/top_users.png')
    plt.close()
    
def heatmap_df(df):
    df['hora'] = df['date'].dt.hour
    df['dia'] = df['date'].dt.day
    matriz = df.pivot_table(index='hora', columns='message_type', values='date', aggfunc='count')
    sns.heatmap(matriz)
    plt.title('Heatmap')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('reports/figures/heatmap.png')
    plt.close()

def plot_all(df):
    plot_atack_time_line(df)
    top_ip(df)
    top_user(df)
    heatmap_df(df)

    
