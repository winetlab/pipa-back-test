from flask import Flask, request, make_response, jsonify
from flask_cors import CORS
import requests
import warnings
import contextlib
from flask_jwt_extended import (
    JWTManager,
)

from urllib3.exceptions import InsecureRequestWarning
from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session

import sys

sys.path.insert(0, "..")
import os
import logging

from db import userDB
from db import politicaDB

from services.freeIPA import FreeIPA
from services.gitLab import GitLab
from services.ranger import Ranger
from services.jenkins import Jenkins

from pathlib import Path
from dotenv import load_dotenv

from flask_restx import Resource, Api,fields
from flask import jsonify


app = Flask("PIPA - Backend")
CORS(app)
api = Api(
    app,
    doc="/doc",
    title="PIPA - Backend",
    version="1.0",
    description="API para integração de políticas de acesso entre FreeIPA, GitLab, Ranger e Jenkins",
)

usuario_ns = api.namespace("user", description="Operações com usuários")
validateuser_ns = api.namespace("validateUser", description="Validação de usuários")
grupos_ns = api.namespace("group", description="Operações para Grupos")
ranger_ns = api.namespace("ranger", description="Operações com Ranger")
gitlab_ns = api.namespace("gitlab", description="Operações com GitLab")
ipa_ns = api.namespace("ipa", description="Operações com FreeIPA")
jenkins_ns = api.namespace("jenkins", description="Operações com Jenkins")
politicas_ns = api.namespace("policy", description="Operações com políticas")

# models para o swagger
projectModel = api.model('projectModel', {
    "id": fields.Integer,
    "name": fields.String
})

gitlabProjectModel = api.model('gitlabModel', {
    "value": fields.Integer,
    "label": fields.String
})

if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.log')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)


dotenv_path = Path("./.env")
load_dotenv(dotenv_path)

# adicionar logs de info para variaveis
FREEIPA_DOMAIN = os.getenv('FREEIPA_DOMAIN')
FREEIPA_ROOT_USERNAME = os.getenv('FREEIPA_ROOT_USERNAME')
FREEIPA_ROOT_PASSWORD = os.getenv('FREEIPA_ROOT_PASSWORD')

GITLAB_DOMAIN = os.getenv('GITLAB_DOMAIN')
GITLAB_ROOT_USERNAME = os.getenv('GITLAB_ROOT_USERNAME')
GITLAB_ROOT_PASSWORD = os.getenv('GITLAB_ROOT_PASSWORD')

WSO2_CLIENT_ID = os.getenv('WSO2_CLIENT_ID')
WSO2_CLIENT_TOKEN = os.getenv('WSO2_CLIENT_SECRET')
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
HOSTNAME_PORT_WSO2 = os.getenv('HOSTNAME_PORT_WSO2')
URL_HOME_FRONT = os.getenv('URL_HOME_FRONT')
CALLBACK_URL = os.getenv('CALLBACK_URL')
APP_URL = os.getenv('APP_URL')

RANGER_DOMAIN = os.getenv('RANGER_DOMAIN')
RANGER_ROOT_USERNAME = os.getenv('RANGER_ROOT_USERNAME')
RANGER_ROOT_PASSWORD = os.getenv('RANGER_ROOT_PASSWORD')
JENKINS_DOMAIN=os.getenv('JENKINS_DOMAIN')
JENKINS_CREATE_URL=os.getenv('JENKINS_CREATE_URL')
JENKINS_ROOT_USERNAME=os.getenv('JENKINS_ROOT_USERNAME')
JENKINS_ROOT_PASSWORD=os.getenv('JENKINS_ROOT_PASSWORD')
JENKINS_ADMIN_TOKEN=os.getenv('JENKINS_ADMIN_TOKEN')


app.logger.debug(FREEIPA_DOMAIN)

if not FREEIPA_DOMAIN:
    app.logger.debug('FreeIPA is not configured.')


IPA = FreeIPA(FREEIPA_DOMAIN, FREEIPA_ROOT_USERNAME, FREEIPA_ROOT_PASSWORD)
GL  = GitLab(GITLAB_DOMAIN, GITLAB_ROOT_USERNAME, GITLAB_ROOT_PASSWORD)
RANGER = Ranger(RANGER_DOMAIN, RANGER_ROOT_USERNAME, RANGER_ROOT_PASSWORD)
JENKINS = Jenkins(JENKINS_DOMAIN, JENKINS_CREATE_URL, JENKINS_ROOT_USERNAME, JENKINS_ROOT_PASSWORD, JENKINS_ADMIN_TOKEN)

# autenticação com OAuth e WSO2
old_merge_environment_settings = requests.Session.merge_environment_settings
app.config['BASE_URL'] = APP_URL
app.config['JWT_SECRET_KEY'] = JWT_SECRET_KEY
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_CSRF_CHECK_FORM'] = True
jwt = JWTManager(app) 

@contextlib.contextmanager
def no_ssl_verification():
    opened_adapters = set()

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        # Verification happens only once per connection so we need to close
        # all the opened adapters once we're done. Otherwise, the effects of
        # verify=False persist beyond the end of this context manager.
        opened_adapters.add(self.get_adapter(url))

        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False

        return settings

    requests.Session.merge_environment_settings = merge_environment_settings

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            yield
    finally:
        requests.Session.merge_environment_settings = old_merge_environment_settings

        for adapter in opened_adapters:
            try:
                adapter.close()
            except:
                pass

oauth = OAuth()
oauth.init_app(app)

# criar utils para funções utilitárias e substituir urls por variaveis
token_endpoint = f'https://{HOSTNAME_PORT_WSO2}/oauth2/token'
# redirect_uri=  URL_HOME_FRONT
redirect_uri=  CALLBACK_URL
scope = ['openid email', 'openid profile']
client = OAuth2Session(client_id=WSO2_CLIENT_ID, client_secret=WSO2_CLIENT_TOKEN, scope=scope, redirect_uri=redirect_uri)
access_token = ''

oauth.register(
    name='wso2',
    client_id= WSO2_CLIENT_ID,
    client_secret= WSO2_CLIENT_TOKEN,
    access_token_endpoint= f'https://{HOSTNAME_PORT_WSO2}/oauth2/token',
    access_token_params=None,
    authorize_endpoint= f'https://{HOSTNAME_PORT_WSO2}/oauth2/authorize',
    authorize_params=None,
    api_base_url=f'https://{HOSTNAME_PORT_WSO2}/',
    client_kwargs={'scope': 'openid email'},
    redirect_uri=  URL_HOME_FRONT,
    callback_url = CALLBACK_URL,
    userinfo_endpoint= f"https://{HOSTNAME_PORT_WSO2}/oauth2/userinfo",
)

@usuario_ns.route("")
class User(Resource):
    
    @usuario_ns.doc(
        params={
            "username": "Nome do usuário que se deseja visualizar. Se não for passado, retorna todos os usuários."
        },
        description="Retorna todos os usuários ou um usuário específico.",
    )
    def get(self):
        try:
            username = request.args.get("username")
            
            if username is None:
                # Tenta obter todos os usuários
                users = userDB.getAllUsers()
                return users
            
            else:
                # Tenta obter o usuário especificado
                user = userDB.getUser(username)
                if user is None:
                    return make_response({
                        "status": "error",
                        "code": 404,
                        "message": "Usuário não encontrado ou não informado."
                    }, 404)
                
                return user
        
        except Exception as e:
            return make_response({
                "status": "error",
                "code": 500,
                "message": f"Ocorreu um erro interno: {str(e)}"
            }, 500)
        
    @usuario_ns.doc(
    body=api.model('userPostModel', {
        "username": fields.String,
        "firstName": fields.String,
        "lastName": fields.String,
        "email": fields.String,
    }),
    description="Cria um usuário.",
)
    def post(self):
        try:
            data = request.get_json()
            app.logger.debug(data)
            firstName = (data["firstName"]).capitalize()
            lastName = (data["lastName"]).capitalize()
            fullName = firstName + " " + lastName
            email = data["email"]
            userName = data["username"]
            validation = "novo"

            result = userDB.insertUser(userName, firstName, lastName, fullName, email, validation)
            return result

        except KeyError as e:
            return f"error : Chave ausente no JSON: {str(e)}", 400

        except ValueError as e:
            return f"error : Valor inválido: {str(e)}", 400

        except Exception as e:
            return f"error : Erro ao criar usuário: {str(e)}", 500

    @usuario_ns.doc(
        body=api.model('userPutModel', {
            "username": fields.String,
            "firstName": fields.String,
            "lastName": fields.String,
            "email": fields.String,
            "usertoupdate": fields.String,
        }),
        description="Atualiza um usuário.",
    )
    def put(self):
        try:
            data = request.get_json()

            firstName = (data["firstName"]).capitalize()
            lastName = (data["lastName"]).capitalize()
            fullName = firstName + " " + lastName
            email = data["email"]
            userName = data["username"]
            userUpdate = data["username"]

            user = userDB.getUser(userName)
            if user is None:
                return make_response({
                    "status": "error",
                    "code": 404,
                    "message": "Usuário não encontrado."
                }, 404)

            result = userDB.updateUser(userUpdate, userName, firstName, lastName, fullName, email)
            return result

        except KeyError as e:
            return jsonify({"error": f"Chave ausente no JSON: {str(e)}"}), 400

        except ValueError as e:
            return jsonify({"error": f"Valor inválido: {str(e)}"}), 400

        except Exception as e:
            return jsonify({"error": f"Erro ao atualizar usuário: {str(e)}"}), 500

    @usuario_ns.doc(
        body=api.model('userDeleteModel', {
            "usertodelete": fields.String,
        }),
        description="Remove um usuário.",
    )
    def delete(self):
        try:
            data = request.get_json()

            userToDelete = data["usertodelete"]

            user = userDB.getUser(userToDelete)

            if user is None or userToDelete is None:
                return make_response({
                    "status": "error",
                    "code": 404,
                    "message": "Usuário não encontrado."
                }, 404)

            result = userDB.deleteUser(userToDelete)
            return result

        except KeyError as e:
            return jsonify({"error": f"Chave ausente no JSON: {str(e)}"}), 400

        except ValueError as e:
            return jsonify({"error": f"Valor inválido: {str(e)}"}), 400

        except Exception as e:
            return jsonify({"error": f"Erro ao deletar usuário: {str(e)}"}), 500



@validateuser_ns.route("")
class validateUser(Resource):
    @validateuser_ns.doc(
        body=api.model('validateUserModel', {
            "username": fields.String,
            "validation": fields.String,
        }),
        description="Valida um usuário.",
    )
    def put(self):
        try:
            data = request.get_json()
            username = data["username"]
            validation = data["validation"]
            
            if not username or not validation:
                return {"error": "Parâmetros inválidos"}, 400

            user = userDB.getUser(username)

            if user is None:
                return make_response({
                    "status": "error",
                    "code": 404,
                    "message": "Usuário não encontrado."
                }, 404)
            
            result = userDB.updateValidation(username, validation)
            
            return result

        except Exception as e:
            print(f"Erro inesperado na função put: {str(e)}")  
            return {"error": "Erro inesperado", "details": str(e)}, 500



@usuario_ns.route("/create")
class createUser(Resource):
    @usuario_ns.doc(
        body=api.model('userCreatePostModel', {
            "username": fields.String,
        }),
        description="Cria um usuário no FreeIpa e no Gitlab.",
    )
    def post(self):
        try:
            data = request.get_json()
            username = data["username"]

            if not username:
                return {"error": "Parâmetros inválidos"}, 400

            result = userDB.getUser(username)

            if result is None :
                return make_response({
                    "status": "error",
                    "code": 404,
                    "message": "Usuário não encontrado."
                }, 404)

            userName = result["username"]
            firstName = result["firstname"]
            lastName = result["lastname"]
            fullName = result["username"] # The full name is the same as the username because LDAP uses full name as cn

           # Add user in FreeIPA
            userIPA = IPA.addUserIPA(firstName, lastName, fullName, userName)

            randonPassword = userIPA["result"]["randompassword"]

            # Authenticate to GitLab to create a user
            GL.createUserGitLab(userName, randonPassword)

            JENKINS.createUserJenkins(userName, randonPassword)


            userDB.updateServicesFlags(userName)

            return "Sucesso ao criar o usuário: " + userName

        except Exception as erro:
            return "Failed to create user: " + str(erro), 500


@usuario_ns.route("/policy")
class userPolicy(Resource):
    @usuario_ns.doc(
        body=api.model('userPostPolicyModel', {
            "policyid": fields.Integer,
            "usernames": fields.List(fields.String),
        }),
        description="Atribui política para o(os) usuário(s)",
    )
    def post(self):
        try:
            data = request.get_json()
            userNames = data["usernames"]
            policyID = data["policyid"]

            policy = politicaDB.getPolicy(policyID)
            
            if policy is None:
                return "Nenhuma política encontrada para o ID fornecido", 404

            for user in userNames:
                userDB.updatePolicyID(user, policyID)

            politicaDB.updatePolicyMembers(policyID, userNames)

            return "Sucesso ao atribuir uma política para o(s) usuário(s)", 200

        except KeyError as e:
            return f"error : Chave ausente no JSON: {str(e)}", 400

        except ValueError as e:
            return f"error : Valor inválido: {str(e)}", 400

        except Exception as e:
            return f"error : Falha ao adicionar usuários no grupo de políticas: {str(e)}", 500


@gitlab_ns.route("/project")
class projectGitLab(Resource):
    @gitlab_ns.doc(description="Retorna todos os projetos do GitLab.")
    def get(self):
        return GL.getProjectsGitLab()

    @gitlab_ns.doc(
        body=api.model('gitlabPostModel', {
            "usernames": fields.List(fields.String),
            "projects": fields.Wildcard(fields.Nested(projectModel, required=True, description='Dicionário de projetos')),
        }),
        description="Associa usuários à projetos",
    )
    def post(self):
        try:
            data = request.get_json()
            
            if not data:
                return "Dados não fornecidos", 400  

            usernames = data.get("usernames")
            projects = data.get("projects")
            accessLevel = "Developer"

            if usernames is None or len(usernames) == 0:
                return "Nenhum usuário fornecido", 400 
            
            if projects is None or len(projects) == 0:
                return "Nenhum projeto fornecido", 400  

            for user in usernames:
                for project_info in projects:
                    projectID = project_info.get("id")

                    if projectID is not None:
                        GL.putUserInAProject(user, projectID, accessLevel)
                    else:
                        return "ID do projeto não encontrado", 400  

            return "Sucesso ao associar os usuários aos projetos do GitLab.", 200  

        except Exception as error:
            return (
                "Não foi possível associar os usuários aos projetos do GitLab: " + str(error),
                500  
            )


@ipa_ns.route("/getGroups")
class getGroupsIPA(Resource):
    @ipa_ns.doc(description="Retorna todos os grupos do FreeIPA.")

    def get(self):
        try:
            result = IPA.getGroupsIPA()
            
            return result
        
        except RuntimeError as e:
            response = {
                "status": "error",
                "code": 500,
                "message": str(e)
            }
            return make_response(jsonify(response), 500)
        
        except Exception as e:
            response = {
                "status": "error",
                "code": 500,
                "message": f"Ocorreu um erro interno: {str(e)}"
            }
            return make_response(jsonify(response), 500)


@ipa_ns.route("/group")
class groupIPA(Resource):
    @ipa_ns.doc(
        body=api.model('ipaPostModel', {
            "usernames": fields.List(fields.String),
            "groupIPA": fields.List(fields.String),
        }),
    )
    def post(self):
        try:
            data = request.get_json()

            usernames = data["usernames"]
            groupIPA = data['groupIPA']

            for user in usernames:
                result = IPA.putUserInGroupIPA(user, groupIPA)

            return result
        
        except RuntimeError as e:
            response = {
                "status": "error",
                "code": 500,
                "message": str(e)
            }
            return make_response(jsonify(response), 500)
        
        except Exception as e:
            response = {
                "status": "error",
                "code": 500,
                "message": f"Ocorreu um erro interno: {str(e)}"
            }
            return make_response(jsonify(response), 500)


@ranger_ns.route("/getPolicies")
class getPoliciesRanger(Resource):
    @ranger_ns.doc(description="Retorna todas as políticas do Ranger.")
    def get(self):
        try:
            result = RANGER.getRangerPolicies()

            return result
        
        except Exception as e:
            response = {
                "status": "error",
                "code": 500,
                "message": f"Ocorreu um erro interno: {str(e)}"
            }
            return make_response(jsonify(response), 500)


@ranger_ns.route("/addToPolicy")
class addToPolicyRanger(Resource):
    @ranger_ns.doc(
        body=api.model('rangerPostModel', {
            "usernames": fields.List(fields.String),
            "rangerpolicies": fields.Wildcard(fields.Nested(projectModel, required=True, description='Dicionário de políticas do ranger')),
        }),
        
        description="Associa usuários à(às) política(s) do Ranger.",
    )
    def post(self):
        try:
            data = request.get_json()

            dictOfUsers = data["usernames"]
            policies = data["rangerpolicies"]

            if policies is not None and len(policies) > 0:
                for policy in policies:
                    policyid = policies[policy]["id"]

                    if policyid is not None:
                        policy = RANGER.retrievePolicyRanger(policyid)
                        RANGER.putUserInPolicyRanger(policy, dictOfUsers)

            else:
                raise Exception("ID(s) da(s) política(s) não infomado(s).", 404)

            return "Sucesso ao associar os usuários à(às) política(s) do Ranger"

        except Exception as error:
            return "Failed to put users in Ranger policies: " + str(error), 500


@ranger_ns.route("/retrievePolicy")
class retrievePolicy(Resource):
    @ranger_ns.doc(
        params={"id": "Id da política que se deseja visualizar."},
        description="Busca política do Ranger.",
    )
    def get(self):
        try:
            data = request.get_json()
            
            policyid = data.get("id")
            
            if policyid is None:
                return make_response(
                    jsonify({
                        "status": "error",
                        "code": 400,
                        "message": "ID da política não fornecido."
                    }), 
                    400
                )
            
            policy = RANGER.retrievePolicyRanger(policyid)
            
            return policy
        
        except Exception as error:
            return make_response(
                jsonify({
                    "status": "error",
                    "code": 500,
                    "message": f"Falha ao recuperar a política do Ranger: {str(error)}"
                }), 
                500
            )

    
@jenkins_ns.route("/assignRole")
class assignRoleJenkins(Resource):
    @jenkins_ns.doc(
        body=api.model('jenkinsPostModel', {
            "usernames": fields.List(fields.String),
            "rolejenkins": fields.List(fields.String),
        }),
        description="Associa roles do Jenkins a usuários da PIPA.",
    )
    def post(self):
        try:
            data = request.get_json()

            usernames = data.get('usernames')
            roles = data.get('rolejenkins')

            if not usernames or not roles:
                return (
                    "status: error, message: Campos 'usernames' e 'rolejenkins' são obrigatórios",
                    400  
                )
            
            try:
                for role in roles:
                    JENKINS.assignOverallPermission(usernames, role)

                return (
                    "status: success, message: Permissões associadas com sucesso",
                    200  
                )

            except Exception as e:
                return (
                    f"status: error, message: Erro ao associar permissões a usuários no Jenkins: {str(e)}",
                    500  
                )
        
        except Exception as e:
            return (
                f"status: error, message: Erro inesperado ao atribuir função no Jenkins: {str(e)}",
                500  
            )
    
@jenkins_ns.route("/getRoles")
class getRolesJenkins(Resource):
    @jenkins_ns.doc(description="Retorna todas as permissões do Jenkins.")
    def get(self):
        try:
            result = JENKINS.getAllRoles()
            return result

        except Exception as e:
            return {
                "status": "error",
                "code": 500,
                "message": f"Ocorreu um erro: {str(e)}"
            }

@politicas_ns.route("")
class policiesPIPA(Resource):
    @politicas_ns.doc(
        params={
            "policyid": "Id do grupo de política que se quer visualizar. Se não for passado, retorna todos os grupos de políticas."
        },
        description="Busca política da PIPA.",
    )

    def get(self):
        policyID = request.args.get('policyid')

        if policyID is None:
            try:
                policies = politicaDB.getAllPolicies()
                return jsonify(policies)

            except Exception as error:
                return f"Falha ao obter as políticas do banco de dados: {str(error)}", 500
        
        try:
            policy = politicaDB.getPolicy(policyID)
            
            if policy is None:
                return "Nenhuma política encontrada para o ID fornecido", 404
            
            return jsonify(policy)
        
        except Exception as error:
            return f"Falha ao obter a política do banco de dados: {str(error)}", 500



    @politicas_ns.doc(
        body=api.model('politicasPipaPostModel', {
            "policyname": fields.String,
            "projectsgitlab": fields.List(fields.Nested(gitlabProjectModel)),
            "groupipa": fields.Nested(projectModel),
            "policiesranger": fields.Nested(projectModel),
            "rolesJenkins": fields.Nested(projectModel),
        }),
    )
    def post(self):
        try:
            data = request.get_json()

            policyName = data["policyname"]

            if "groupipa" in data and "name" in data["groupipa"]:
                groupIPA = data["groupipa"]["name"]
            else:
                groupIPA = ""

            projectsGitLab = {}
            for p in data["projectsgitlab"]:
                pID = p["value"]
                pName = p["label"]
                pGL = {pName: {"id": pID, "name": pName}}
                projectsGitLab.update(pGL)

            policiesranger = {}
            for p in data["policiesranger"]:
                pID = p["value"]
                pName = p["label"]
                pRanger = {pName: {"id": pID, "name": pName}}
                policiesranger.update(pRanger)

            rolesJenkins = {}
            for r in data["rolesJenkins"]:
                rID = r["value"]
                rName = r["label"]
                rJenkins = {rName: {"id": rID, "name": rName}}
                rolesJenkins.update(rJenkins)

            result = politicaDB.insertPolicy(
                policyName, projectsGitLab, groupIPA, policiesranger, rolesJenkins
            )

            return result

        except Exception as error:
            return "Failed to insert the policy into database:" + str(error), 500

    @politicas_ns.doc(
        body=api.model('politicasPipaDeleteModel', {
            "policytodelete": fields.String,
        }),
        description="Remove política na PIPA.",
    )
    def delete(self):
        try:
            data = request.get_json()

            policyToDelete = data["policytodelete"]

            if policyToDelete is None or policyToDelete.strip() == '':
                return "O argumento policytodelete é obrigatório", 404

            policy = politicaDB.getPolicy(policyToDelete)
            
            if policy is None:
                return "Nenhuma política encontrada para o ID fornecido", 404

            result = politicaDB.deletePolicy(policyToDelete)

            return result

        except Exception as error:
            return "Failed to delete the policy in database: " + str(error), 500


@politicas_ns.route("/members")
class policyMembers(Resource):
    
    @politicas_ns.doc(
        params={"policyid": "ID da política que se deseja visualizar membros."},
        description="Lista membros de política da PIPA.",
    )
    def get(self):
        policyID = request.args.get("policyid")

        if not policyID or not policyID.strip():
            return "ID da política não fornecido ou inválido", 400  

        try:
            result = politicaDB.getMemberPolicy(policyID)

            if result is None:
                return "Nenhuma política encontrada para o ID fornecido", 404  

            return result

        except Exception as error:
            return (
                "Falha ao obter os membros de uma política do banco de dados: " + str(error),
                500  
            )



if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
