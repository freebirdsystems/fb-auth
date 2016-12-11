'use strict';

angular
    .module('authService', [])
    .factory('AuthService', AuthService);


function AuthService($cookies, $q, $http) {

    var initResponse;
    var domain;


    var setToken = function (token) {
        $cookies.put('_token', token, {domain: domain});
    };


    var getToken = function (cookieHost) {
        return $cookies.get('_token', {domain: cookieHost});
    };


    var setInit = function (response) {
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

            $cookies.remove('_token', {domain: domain});
            deferred.resolve(response);
            
        }, function (response) {
            deferred.reject(response);
        });

        return deferred.promise;

    };


    var login = function (path, data) {

        var deferred = $q.defer();

        $http({
            method: 'POST',
            url: path,
            data: data
        }).then(function (response) {

            setToken(response.data.token);
            setInit(response.data.bootstrap_loader);
            deferred.resolve(response);

        }, function (response) {
            deferred.reject(response);
        });

        return deferred.promise;

    };


    return {

        login: login,
        getHeaders: getHeaders,
        logout: logout,
        getToken: getToken,
        getInit: getInit,
        setInit: setInit

    };
}
