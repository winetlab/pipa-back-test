from python_freeipa import ClientMeta



class FreeIPA:

    def __init__ (self, FREEIPA_DOMAIN, FREEIPA_ROOT_USERNAME, FREEIPA_ROOT_PASSWORD):
        self.FREEIPA_DOMAIN = FREEIPA_DOMAIN
        self.FREEIPA_ROOT_USERNAME = FREEIPA_ROOT_USERNAME
        self.FREEIPA_ROOT_PASSWORD = FREEIPA_ROOT_PASSWORD


    def ipaAuth(self):

        client = ClientMeta(self.FREEIPA_DOMAIN, verify_ssl=False)
        client.login(self.FREEIPA_ROOT_USERNAME, self.FREEIPA_ROOT_PASSWORD)

        return client
        
  
    def addUserIPA(self, firstName, lastName, fullName, userName):
        

        try:
            client = self.ipaAuth()
            user = client.user_add(a_uid= userName, 
                                o_givenname=firstName, 
                                o_sn=lastName, 
                                o_cn=fullName,
                                o_random=True,
                                o_preferredlanguage='EN'
                                )

            return user
            
        except (Exception) as erro:
            return f"Falha ao criar usuário no FreeIPA {str(erro)}", 500

    def getGroupsIPA(self):
        try:
            client = self.ipaAuth()  
            groups = client.group_find()  

            listOfGroupsIPA = [] 

            for g in groups['result']:
                if 'gidnumber' in g and 'cn' in g and g['cn']:  
                    group_info = {
                        'id': g['gidnumber'][0],  
                        'name': g['cn'][0]  
                    }
                    listOfGroupsIPA.append(group_info)  

            return listOfGroupsIPA  

        except Exception as erro:
            raise RuntimeError(f"Falha ao recuperar grupos do FreeIPA: {str(erro)}")

            

    def putUserInGroupIPA(self, userName, groupName):

        try:
            client = self.ipaAuth()

            #group = client.group_find(o_gidnumber= groupID)
            #group_cn = group['result'][0]['cn'][0]
            group_cn = groupName

            client.group_add_member(a_cn=group_cn, o_user=userName)

        except Exception as erro:
            raise RuntimeError(f"Falha ao associar usuários a um grupo do FreeIPA: {str(erro)}")




        


       
