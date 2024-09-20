import psycopg2
from psycopg2.extras import RealDictCursor
import os


def startConnectionDB():

    cur, conn = None, None

    try:
        conn = psycopg2.connect(
                host= os.getenv('DB_HOST'),
                port = os.getenv('DB_PORT'),
                database= os.getenv('DB_NAME'),
                user= os.getenv('DB_USER'),
                password= os.getenv('DB_PASSWORD'))

        cur = conn.cursor(cursor_factory=RealDictCursor)

        return cur, conn
    
    except(Exception, psycopg2.Error) as error:
       raise Exception("Failed to connect to the database" + str(error))



def closeConnectionDB(cur, conn):
    cur.close()
    conn.close()



def insertUser(username, firstName, lastName, fullName , email, validation):

    cur, conn = None, None
    
    try:
        cur, conn = startConnectionDB()

        cur.execute('INSERT INTO usuarios (username, firstName, lastName, fullName, email, iscreatedipa, iscreatedgitlab, validation)'
                    'VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
                    (username, firstName, lastName, fullName, email, False, False, validation)
                    )
        
        conn.commit()

        closeConnectionDB(cur, conn)

        return "Sucesso ao adicionar o usuário " + username
    
    except(psycopg2.errors.UniqueViolation):
        raise Exception("Username already exists!")
    
    except(psycopg2.Error) as error: #FIX
        raise Exception("Failed to insert user into database:" + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)


def getUser(username):
    cur, conn = None, None
    try:
        cur, conn = startConnectionDB()

        cur.execute("SELECT username, policyid, firstname, lastname, fullname, email, iscreatedipa, iscreatedgitlab, validation FROM usuarios WHERE username = %s", (username,))
        
        result = cur.fetchone()
        
        closeConnectionDB(cur, conn)
        return result
    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Failed to get user from database: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)


def updateUser(userUpdate, userName, firstName, lastName, fullName, email):
    cur, conn = None, None

    try:
        cur, conn = startConnectionDB()

        cur.execute('''
                        UPDATE usuarios
                        SET 
                            username= %s,
                            firstName=%s,
                            lastName=%s,
                            fullName=%s,
                            email=%s
                        WHERE 
                            username=%s
                    '''
                    ,(userName, firstName, lastName, fullName, email, userUpdate)
                    )

        conn.commit()

        closeConnectionDB(cur, conn)

        return "Sucesso ao atualizar o usuário " + userName
        
    
    except(Exception, psycopg2.Error) as error:
        return jsonify({"error": f"Failed to update user in database: {str(error)}"}), 500
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)


def deleteUser(usertodelete):
    cur, conn = None, None

    try:
        cur, conn = startConnectionDB()

        cur.execute('DELETE FROM usuarios WHERE username=%s', (usertodelete,))

        conn.commit()

        closeConnectionDB(cur, conn)
        
        return "Sucesso ao deletar o usuário " + usertodelete
    
    except(Exception, psycopg2.Error) as error:
        return jsonify({"error": f"Failed to delete user in database: {str(error)}"}), 500
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)


def updateServicesFlags(username):
    cur, conn = None, None

    try:
        cur, conn = startConnectionDB()

        cur.execute('''
                        UPDATE usuarios
                        SET 
                            iscreatedipa= %s,
                            iscreatedgitlab=%s
                        WHERE 
                            username=%s
                    '''
                    ,(True, True, username)
                    )

        conn.commit()

        closeConnectionDB(cur, conn)

        return "Sucesso ao atualizar flags de serviço"
        
    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Failed to update services in database: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)



def updateValidation(username, validation):
    cur, conn = None, None
    try:
        cur, conn = startConnectionDB()

        cur.execute('''
                        UPDATE usuarios
                        SET 
                            validation=%s
                        WHERE 
                            username=%s
                    '''
                    ,(validation, username)
                    )

        conn.commit()

        closeConnectionDB(cur, conn)

        return "Sucesso ao validar usuário"
        
    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Failed to update services in database: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)


def getAllUsers():
    cur, conn = None, None
    try:
        cur, conn = startConnectionDB()

        cur.execute("SELECT username, policyid, firstname, lastname, fullname, email, validation from usuarios")
        
        result = cur.fetchall()
        closeConnectionDB(cur, conn)
        return result

    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Failed to get user from database:" + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)


def updatePolicyID(username, policyID):

    cur, conn = None, None
    try:
        cur, conn = startConnectionDB()
        cur.execute("SELECT policyid from usuarios where username=%s", (username,))
        result = cur.fetchone()

        policyIds = []

        policyIds.append(int(policyID))

        if(result['policyid'] != None):   
            for policies in result['policyid']:
                policyIds.append(int(policies))   

 
       
        cur.execute(
                        '''
                        UPDATE usuarios
                        SET 
                            policyid= %s
                        WHERE 
                            username=%s
                        '''
                    ,(policyIds, username)
                    )

        conn.commit()
        closeConnectionDB(cur, conn)
        
        return "Sucesso ao atribuir uma política para o usuário"
        
    
    except(Exception, psycopg2.Error) as error:
        raise Exception("Failed to update policy id of user: " + str(error))
    
    finally:
        if conn:
            closeConnectionDB(cur, conn)