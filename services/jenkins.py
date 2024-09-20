from .rolestrategy import Role
from .rolestrategy import RoleStrategy
from .rolestrategy import GetRole

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
import time
import json


class Jenkins:
    def __init__(
        self,
        JENKINS_DOMAIN,
        JENKINS_CREATE_URL,
        JENKINS_ROOT_USERNAME,
        JENKINS_ROOT_PASSWORD,
        JENKINS_ADMIN_TOKEN,
    ):
        self.JENKINS_DOMAIN = JENKINS_DOMAIN
        self.JENKINS_CREATE_URL = JENKINS_CREATE_URL
        self.JENKINS_ROOT_USERNAME = JENKINS_ROOT_USERNAME
        self.JENKINS_ROOT_PASSWORD = JENKINS_ROOT_PASSWORD
        self.JENKINS_ADMIN_TOKEN = JENKINS_ADMIN_TOKEN

    def createUserJenkins(self, username, randonPassword):
        # options = FirefoxOptions()

        service = Service(executable_path="/geckodriver")
        # Testar local com "/snap/bin/geckodriver"
        options = webdriver.FirefoxOptions()
        # browser = webdriver.Firefox(service=service, options=options)

        options.add_argument("--headless")  # torna o firefox invisivel
        driver = webdriver.Firefox(
            options=options
        )  # testar local inclua service=service
        driver.get(self.JENKINS_DOMAIN + "/login")
        time.sleep(2)

        # Inicialização do driver do navegador

        # Preenche os campos de entradra
        # Digita o usuário do root/admin
        username_input_login = driver.find_element(
            by="name", value="j_username"
        )  # find_element_by_id("j_username")
        username_input_login.send_keys(username)

        # digita a senha do root/admin
        password_input = driver.find_element(
            by="name", value="j_password"
        )  # find_element_by_id("password")
        password_input.send_keys(randonPassword)

        # clica no botão de entrar
        # Pode pressionar Enter após preencher a senha para enviar o formulário
        password_input.send_keys(Keys.RETURN)

        # Encerra o driver
        driver.quit()

    def assignOverallPermission(self, usernames, role):
        try:
            rs = RoleStrategy(
                self.JENKINS_DOMAIN,
                self.JENKINS_ROOT_USERNAME,
                self.JENKINS_ROOT_PASSWORD,
                ssl_verify=True,
                ssl_cert=None,
            )
            initial_role = Role(rs, "globalRoles", role)

        except Exception as e:
            error_message = f"Erro no RoleStrategy: {str(e)}"
            print(error_message)
            raise RuntimeError(error_message)

        for user in usernames:
            try:
                initial_role.assign_sid(user)
            except Exception as e:
                error_message = f"Erro ao atribuir função ao usuário {user}: {str(e)}"
                print(error_message)
                raise RuntimeError(error_message)

        return "Permissões associadas com sucesso"


    def getAllRoles(self):
        try:
            rs = RoleStrategy(
                self.JENKINS_DOMAIN,
                self.JENKINS_ROOT_USERNAME,
                self.JENKINS_ROOT_PASSWORD,
                ssl_verify=True,
                ssl_cert=None,
            )

            listing = GetRole(rs, "globalRoles")
            list_of_roles = listing.list_roles()

            roles = []
            for key, value in list_of_roles.items():
                count = len(value)
                formatted_item = {"label": key, "value": count}
                roles.append(formatted_item)

            return roles

        except Exception as e:
            error_message = f"Erro ao obter os papéis: {str(e)}"
            print(error_message)
            raise RuntimeError(error_message)

