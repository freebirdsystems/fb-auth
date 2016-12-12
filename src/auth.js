'use strict';

angular
    .module('auth', [])
    .factory('AuthenticationService', AuthenticationService)
    .factory('AuthorizationService', AuthorizationService)
    .directive('hasPermission', hasPermission);


function hasPermission(AuthorizationService){
  return {
    link: function(scope, element, attrs) {
      if(!_.isString(attrs.hasPermission)) {
        throw 'hasPermission value must be a string'
      }
      var value = attrs.hasPermission.trim();
      var notPermissionFlag = value[0] === '!';
      if(notPermissionFlag) {
        value = value.slice(1).trim();
      }

      function toggleVisibilityBasedOnPermission() {
        var hasPermission = AuthorizationService.hasPermission(value);
        if(hasPermission && !notPermissionFlag || !hasPermission && notPermissionFlag) {
          element.removeClass('ng-hide');
        }
        else {
          element.addClass('ng-hide');
        }
      }

      toggleVisibilityBasedOnPermission();
      scope.$on('permissionsChanged', toggleVisibilityBasedOnPermission);
    }
  }
}




function AuthenticationService($cookies, $q, $http, AuthorizationService, $location) {

    var initResponse;
    var domain;


    var removeToken = function(){
        $cookies.remove('_token', {'domain': domain});
        $location.path('/login');
    }

    var setToken = function (token, cookieHost) {
        domain = cookieHost;
        $cookies.put('_token', token, {'domain': domain});
    };


    var getToken = function (cookieHost) {
        return $cookies.get('_token', {'domain': domain});
    };


    var setInit = function (response) {
        AuthorizationService.setPermissions(response.user.positions.active.permissions);
        initResponse = response;
    };


    var getInit = function () {
        return initResponse;
    };


    var getHeaders = function (cookieHost) {

        domain = cookieHost;

        var _token = getToken(domain);

        if (_token) {
            var obj = {'X-Authorization': _token};
            return obj
        }

    };


    var logout = function (path) {

        var deferred = $q.defer();

        $http({
            method: 'GET',
            url: path,
            headers: {
                'X-Authorization': getToken()
            }
        }).then(function (response) {

            $cookies.remove('_token', {'domain': domain});
            $location.path('/login');
            deferred.resolve(response);
            
        }, function (response) {
            deferred.reject(response);
        });

        return deferred.promise;

    };


    var login = function (path, data, cookieHost) {

        var deferred = $q.defer();

        $http({
            method: 'POST',
            url: path,
            data: data
        }).then(function (response) {

            setToken(response.data.token, cookieHost);
            setInit(response.data.bootstrap_loader);
            deferred.resolve(response);

        }, function (response) {
            deferred.reject(response);
        });

        return deferred.promise;

    };


    return {

        login       : login,
        getHeaders  : getHeaders,
        logout      : logout,
        getToken    : getToken,
        getInit     : getInit,
        setInit     : setInit,
        setToken    : setToken,
        removeToken : removeToken

    };
}


function AuthorizationService($rootScope){

    var permissionList;

    return {
        setPermissions: function(permissions) {
          permissionList = permissions;
          $rootScope.$broadcast('permissionsChanged');
        },
        hasPermission: function (permission) {
          permission = permission.trim();
          return permissionList[permission];
        }
    };
}



