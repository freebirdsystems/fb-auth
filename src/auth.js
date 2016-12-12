'use strict';

angular
    .module('auth', [])
    .factory('AuthenticationService', AuthenticationService)
    .factory('AuthorizationService', AuthorizationService)
    .directive('hasPermission', hasPermission);


function hasPermission(AuthorizationService){
    return {
        restrict:'A',
        scope:{
            asArray:'=?',
        },
        link: function(scope, element, attrs) {
             
            if(scope.asArray) {
               toggleByArray()
            } 
            else if (typeof attrs.hasPermission === "string"){
               toggleByString()
            }

            function toggleByString() {
               var value = attrs.hasPermission.trim();

               var hasPermission = AuthorizationService.hasPermission(value);

               if(hasPermission) {
                element.removeClass('ng-hide');
               }
               else {
                element.addClass('ng-hide');
               }
               scope.$on('permissionsChanged', toggleByString);
            }    

            function toggleByArray() {
               var show = false;
               var values = [];
               var elemArr = element.find('ul li');

               for(var idx=0 ; idx<elemArr.length ; ++idx){
                 var thisElem = elemArr[idx];
                 values.push(thisElem.getAttribute('has-permission'))
               }

               values.forEach(function(value){
                 var hasPermission = AuthorizationService.hasPermission(value);
                 if(hasPermission){
                   show = true;
                 }
               })

               if(show) {
                 element.show();
               }
               else {
                 element.hide();
               }
               scope.$on('permissionsChanged', toggleByString);
            }
        }    
             
    }
}


function AuthenticationService($cookies, $q, $http, AuthorizationService) {

    var initResponse;
    var domain;


    var setToken = function (token, cookieHost) {
        domain = cookieHost;
        $cookies.put('_token', token, {'domain': domain});
    };


    var getToken = function (cookieHost) {
        return $cookies.get('_token', {'domain': domain});
    };


    var setInit = function (response) {
        AuthorizationService.setPermissions(response.user.positions.active.permissions);
        debugger
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
        setToken    : setToken

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



