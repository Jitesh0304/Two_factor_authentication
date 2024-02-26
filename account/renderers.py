from rest_framework import renderers
import json


    ## custom render class to show the error message
class UserRenderer(renderers.JSONRenderer):
    charset = "utf-8"
    ## override the render function
    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = ''
        if 'ErrorDetail' in str(data):
            response = json.dumps({'error':data})
        else:
            response = json.dumps(data)
        return response