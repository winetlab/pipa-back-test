# test_ranger.py
from flask import jsonify
from apache_ranger.model.ranger_service import *
from apache_ranger.client.ranger_client import *
from apache_ranger.model.ranger_policy  import *

class Ranger:

    def __init__ (self, RANGER_DOMAIN, RANGER_ROOT_USERNAME, RANGER_ROOT_PASSWORD):
        self.RANGER_DOMAIN = RANGER_DOMAIN
        self.RANGER_ROOT_USERNAME = RANGER_ROOT_USERNAME
        self.RANGER_ROOT_PASSWORD = RANGER_ROOT_PASSWORD


    def rangerAuth(self):

        ranger_url = self.RANGER_DOMAIN
        ranger_auth = (self.RANGER_ROOT_USERNAME, self.RANGER_ROOT_PASSWORD)
        ranger = RangerClient(ranger_url, ranger_auth)

        return ranger

    def getRangerPolicies(self):
        try:
            ranger = self.rangerAuth()  
            policies = ranger.find_policies()  

            listOfRangerPolicies = []  

            for policy in policies:
                policy_info = {
                    'value': policy["id"],   
                    'label': policy["name"]  
                }
                listOfRangerPolicies.append(policy_info)  

            return listOfRangerPolicies  

        except Exception as erro:
            return {
                "status": "error",
                "code": 500,
                "message": f"Falha ao obter políticas no Ranger: {str(erro)}"
            }
    

            
    def retrievePolicyRanger(self, policyid):
        try:
            ranger = self.rangerAuth()
            retrieved_policy = ranger.get_policy_by_id(policyid)
            return retrieved_policy

        except Exception as erro:
            raise Exception(f"Falha ao recuperar a política no Ranger: {str(erro)}")


    
    def putUserInPolicyRanger(self, policy, dictOfUsers):
        try:
            ranger = self.rangerAuth()
            policy.policyItems[0]["users"] = policy.policyItems[0]["users"] + dictOfUsers
            policy.policyItems[0]["accesses"][0]["type"] = 'read'
            ranger.update_policy_by_id(policy.id, policy)

        except Exception as erro:
            raise Exception(f"Falha ao adicionar usuário à política no Ranger: {str(erro)}")


