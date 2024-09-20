import gitlab
import requests
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service
import time
import subprocess

class GitLab():

    def __init__ (self, GITLAB_DOMAIN, GITLAB_ROOT_USERNAME, GITLAB_ROOT_PASSWORD):
        self.GITLAB_DOMAIN = GITLAB_DOMAIN
        self.GITLAB_ROOT_USERNAME = GITLAB_ROOT_USERNAME
        self.GITLAB_ROOT_PASSWORD = GITLAB_ROOT_PASSWORD

    def createUserGitLab(self, userName, randonPassword):
        try:
            #options = FirefoxOptions()

            service = Service(executable_path="/snap/bin/geckodriver")

            options = webdriver.FirefoxOptions()

            #browser = webdriver.Firefox(service=service, options=options)

            options.add_argument("--headless")
            driver = webdriver.Firefox(options=options)
            driver.get(self.GITLAB_DOMAIN+'/users/sign_in')
            time.sleep(2)

            # Inicialização do driver do navegador
            
            id_box = driver.find_element(by="name", value='username')
            id_box.send_keys(userName)

            pass_box = driver.find_element(by="name", value='password')
            pass_box.send_keys(randonPassword)

            pass_box.send_keys(Keys.ENTER)
        
            driver.quit()
        
        except Exception as e:
            print(f"Ocorreu um erro: {e}")


    def createConnectionWithGitLab(self):
        res = requests.post(self.GITLAB_DOMAIN+'/oauth/token',
                        data={
                            "grant_type" : "password",
                            "username"   : self.GITLAB_ROOT_USERNAME,
                            "password"   : self.GITLAB_ROOT_PASSWORD
                        })
        
        token = res.json()
        token = token['access_token']

        gl = gitlab.Gitlab(url=self.GITLAB_DOMAIN, oauth_token=token, api_version=4) 

        return gl

    def getProjectsGitLab(self):

        try:
            gl = self.createConnectionWithGitLab()

            projects = gl.projects.list()
            listOfProjects = [] 

            for p in projects:
                projects_info = {
                    'value': p.id,  
                    'label': p.name  
                }
                listOfProjects.append(projects_info)  

            return listOfProjects  
        
        except Exception as erro:
            raise Exception("Failed to get projects in Gitlab: " + str(erro))


    def userIsMemberOfAProject(self, userName, idProject):
        try:
            gl = self.createConnectionWithGitLab()

            project = gl.projects.get(idProject)
            members = project.members.list()

            membersList = []

            for user in members:
                membersList.append(user.username)

            if(userName in membersList):
                print(userName)
                return True
            else:
                return False
        
        except Exception as erro:
            return "Failed to verify user: " + str(erro)


    def putUserInAProject(self, userName, idProject, accessLevel):

        try:

            gl = self.createConnectionWithGitLab()

            user = gl.users.list(search=userName)
            idUser = user[0].id

            project = gl.projects.get(idProject)

            if(accessLevel == 'Guest'):
                accessLevel = gitlab.const.AccessLevel.GUEST
            if(accessLevel == 'Reporter'):
                accessLevel = gitlab.const.AccessLevel.REPORTER
            if(accessLevel == 'Developer'):
                accessLevel = gitlab.const.AccessLevel.DEVELOPER
            if(accessLevel == 'Maintainer'):
                accessLevel = gitlab.const.AccessLevel.MAINTAINER
            if(accessLevel == 'Owner'):
                accessLevel = gitlab.const.AccessLevel.OWNER

            member = project.members.create({ 'user_id': idUser,
                                            'access_level': accessLevel})

            return "O usuário " + userName + " foi adicionado ao projeto com sucesso!"

        except Exception as erro:
            raise Exception("Failed to link user to a Gitlab project: " + str(erro)) 



    # Need to finalize
    def putUserInGroupGitLab(self, userName):
 
        gl = self.createConnectionWithGitLab()

        user = gl.users.list(search=userName)
        idUser = user[0].id

        groups = gl.groups.list()
        group = groups[2]

        members = group.members.list()
        member = group.members.create({'user_id': idUser,
                                        'access_level': gitlab.const.AccessLevel.DEVELOPER})

