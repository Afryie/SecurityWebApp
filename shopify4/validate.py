import FlaskCerberus

def validate(data):

    schema={'type':{'allowed': ['Customer','Seller'],'required':True},
            'name':{'type':'string','regex':'^[a-zA-Z]+$','required':True},
            'email':{'type':'string','regex': '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$','required':True},
            'phone':{'type': 'string','regex': '^[0-9]+$','minlength':9, 'maxlength':9,'required':True},
            'locality':{'required':False},
            'city':{'required':False},
            'state':{'required':False},
            'country':{'required':False},
            'zip':{'type':'string','regex': '^[0-9-]+$','minlength':3, 'maxlength':7,'required':True},
            'password':{'type':'string', 'minlength':8, 'maxlength':40,'required':True},
            'cnfrm_psswd': {'type': 'string', 'minlength': 8, 'maxlength': 40,'required':True},

            }
    v=FlaskCerberus.Validator(schema)
    v.allow_unknown = True
    is_ok = v.validate(data)

    if data['password'] != data['cnfrm_psswd']:
        return False,'Password missmatch'


    return is_ok, v.errors


data= { 'type': 'Customer','name': 'add', 'email': 'a@a.pl', 'phone': '12345678', 'area': 'a', 'locality': 'a','city': 'a' , 'state': 'a', 'country': 'a', 'zip': '123-456', 'password': 'asdfghjk', 'cnfrm_psswd': 'asdfghjk'}
x,y=validate(data)
print(x)
print(y)

"""
if y["phone"] == True:
    print('its a phone!')
if y['zip'] == True:
    print('its a zip!')
"""
if 'zip' in y.keys():
    print('its a zip!')
if 'phone' in y.keys():
    print('its a phone!')