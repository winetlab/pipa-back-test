import psycopg2
from psycopg2.extras import Json, RealDictCursor
import os

def startConnectionDB():
    cur, conn = None, None

    try:
        conn = psycopg2.connect(
                host=os.getenv('DB_HOST'),
                port=os.getenv('DB_PORT'),
                database=os.getenv('DB_NAME'),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD'))

        cur = conn.cursor(cursor_factory=RealDictCursor)

        return cur, conn
    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Falha ao conectar-se ao banco de dados: " + str(error))


def closeConnectionDB(cur, conn):
    cur.close()
    conn.close()

def insertPolicy(policyName, projectsGitLab, groupIPA, policiesranger, rolesJenkins):
    cur, conn = None, None
    
    try:
        cur, conn = startConnectionDB()

        cur.execute('INSERT INTO politicas ("name", projectsgitlab, groupipa, policiesranger, rolesJenkins)'
                    'VALUES (%s, %s, %s, %s, %s)',
                    (policyName, Json(projectsGitLab), groupIPA, Json(policiesranger), Json(rolesJenkins))
                    )

        conn.commit()

        closeConnectionDB(cur, conn)

        return "Sucesso ao adicionar a política " + policyName
    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Falha ao inserir a política no banco de dados: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)

def getPolicy(policyID):
    cur, conn = None, None
    try:
        cur, conn = startConnectionDB()

        cur.execute("SELECT policyid, name, projectsgitlab, groupipa, members, policiesranger, rolesJenkins FROM politicas WHERE policyID = %s", (policyID,))
        
        result = cur.fetchone()
        
        closeConnectionDB(cur, conn)
        return result
    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Falha ao obter a política do banco de dados: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)

def updatePolicy(policyID, policyName, projectsGitLab, policiesranger, groupipa, rolesJenkins):
    cur, conn = None, None

    try:
        cur, conn = startConnectionDB()

        cur.execute('''
                        UPDATE politicas
                        SET 
                            name=%s,
                            projectsgitlab=%s,
                            policiesranger=%s,
                            groupipa=%s,
                            rolesJenkins=%s
                        WHERE 
                            policyID=%s
                    ''',
                    (policyName, Json(projectsGitLab), Json(policiesranger), str(groupipa), Json(rolesJenkins), policyID)
                    )

        conn.commit()

        closeConnectionDB(cur, conn)

        return "Sucesso ao atualizar a política!"
        
    except(Exception, psycopg2.Error) as error:
        raise Exception("Falha ao atualizar os dados da política no banco de dados: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)

def deletePolicy(policyID):
    cur, conn = None, None
    try:
        cur, conn = startConnectionDB()

        cur.execute('DELETE FROM politicas WHERE policyID=%s', (policyID,))

        conn.commit()

        closeConnectionDB(cur, conn)
        
        return "Sucesso ao deletar a política!"
    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Falha ao deletar a política no banco de dados: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)

def getAllPolicies():
    cur, conn = None, None
    try:
        cur, conn = startConnectionDB()

        cur.execute("SELECT * FROM politicas")
        
        result = cur.fetchall()
        
        closeConnectionDB(cur, conn)
        return result

    except(Exception, psycopg2.Error) as error:
        raise Exception("Falha ao obter as políticas do banco de dados: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)

def updatePolicyMembers(policyID, members):
    cur, conn = None, None

    try:
        cur, conn = startConnectionDB()

        cur.execute('''
                        UPDATE politicas
                        SET  
                            members=%s
                        WHERE 
                            policyID=%s
                        ''',
                        (members, policyID)
                        )

        conn.commit()
        closeConnectionDB(cur, conn)

        return "Sucesso ao inserir membros na política."
        
    except(Exception, psycopg2.Error) as error:
        raise Exception("Falha ao inserir dados de membros na política no banco de dados: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)

def getMemberPolicy(policyID):
    cur, conn = None, None
    try:
        cur, conn = startConnectionDB()

        cur.execute("SELECT members FROM politicas WHERE policyID = %s", (policyID,))
        
        result = cur.fetchone()
        
        closeConnectionDB(cur, conn)
        return result
    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Falha ao obter os membros de uma política do banco de dados: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)