from django.shortcuts import render
import logging
from django.core.mail import mail_admins

logger = logging.getLogger('main')



class Handle404Middleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if response.status_code in [404, 403]:
            try:
                self.log_request_details(request)
            except Exception as e:
                logger.error(f"Error logging request details: {str(e)}")
            return self.handle_404(request)
        
        return response

    def log_request_details(self, request):
        logger.info('Unknown endpoint')
        logger.info(f"Host Name: {request.get_host()}")
        logger.info(f"Client IP: {request.META.get('REMOTE_ADDR')}")
        logger.info(f"Request Path: {request.path}")
        logger.info(f"User Agent: {request.META.get('HTTP_USER_AGENT')}")
        logger.info(f"Referer: {request.META.get('HTTP_REFERER')}")
        logger.info(f"Request Method: {request.method}")
        logger.info(f"Cookies: {request.COOKIES}")
        logger.info(f"Query Params: {request.GET.dict()}")


        if request.method in ['POST', 'PUT', 'PATCH']:
            logger.info(f"Request Payload: {request.body.decode('utf-8')}")

        if hasattr(request, 'session'):
            logger.info(f"Session Info: {dict(request.session.items())}")

    def handle_404(self, request):
        requested_endpoint = request.path
        return render(request, 'account/error_template.html', {'requested_endpoint': requested_endpoint}, status=404)





# class Handle404Middleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         response = self.get_response(request)
#         # if response.status_code == 404:
#         if response.status_code in [404, 403]:
#             logger.info('Unknown endpoint')
#             logger.info(request)                                
#             logger.info(request.get_host())                     ##  host_name
#             logger.info(request.META.get('REMOTE_ADDR'))        ##  client_ip 
#             logger.info(request.path)                           ##  path 
#             logger.info(request.META.get('HTTP_USER_AGENT'))    ##  user_agent 
#             logger.info(request.META.get('HTTP_REFERER'))       ##  referer 
#             logger.info(request.method)                         ##  request_method 
#             logger.info(request.COOKIES)                        ##  cookies

#                                                     ## request_payload or request_data
#             logger.info(request.body.decode('utf-8')) if request.method in ['POST', 'PUT', 'PATCH'] else None
#             logger.info(request.GET.dict())                     ##  query_params
#             logger.info(request.session.items())  ## session_info               if session is enabled 

#             return self.handle_404(request)
#         return response

#     def handle_404(self, request):
#         requested_endpoint = request.path
#         # return render(request, 'account/error_template.html', status=404)
#         return render(request, 'account/error_template.html', {'requested_endpoint': requested_endpoint}, status=404)
