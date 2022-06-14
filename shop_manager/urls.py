"""cholojai URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls.static import static
from django.contrib import admin
from django.conf.urls import url
from django.urls import path, include


from shop_manager.settings import env, STATIC_URL, MEDIA_URL, STATIC_ROOT, MEDIA_ROOT

api_url_patterns = (
    [
        path('accounts/', include('accounts.api.v1.urls')),
    ], 'api'
)
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('accounts.urls')),
    path('api-auth/', include('rest_framework.urls')),
    path('api/v1/', include(api_url_patterns))
]

if env.str('ENV_TYPE') == 'DEVELOPMENT':
    import debug_toolbar

    urlpatterns += static(STATIC_URL, document_root=STATIC_ROOT)
    urlpatterns += static(MEDIA_URL, document_root=MEDIA_ROOT)

    urlpatterns += [path('__debug__/', include(debug_toolbar.urls))]
