'use strict';

angular
  .module('authService')
  .factory('AuthService', AuthService);


function AuthService($cookies, $q, $http, ENV) {

  var initResponse;

  return {

    /**
     * @name setHeaders
     * @desc
     */
    setHeaders: function () {

      var _token = this.getToken();

      var obj = {};
      if (_token) {
        obj = {'X-Authorization': _token};
      }
      Restangular.setDefaultHeaders(obj);
    },


    /**
     * @name setToken
     * @desc
     * @param token
     */
    setToken: function (token, domain) {
      $cookies.put('_token', token, { domain: domain });
    },



    setInit : function(response){
      initResponse = response;
    },


    getInit: function(){
      return initResponse;
    },

    /**
     * @name getToken
     * @desc
     * @returns {*|string}
     */
    getToken: function () {
      return $cookies.get('_token', { domain: domain });
    },


    /**
     * @name logout
     * @desc
     * @returns {*}
     */
    logout: function (path, domain) {

      $http({
            method: 'GET',
            url: path
           }).then(function (response) {
              $cookies.remove('_token', { domain: domain });
           }, function (response) {
    
           });

    },


    /**
     * @name login
     * @desc
     * @param user
     * @returns {*}
     */
    login: function (path, data) {

      var deferred = $q.defer();

      $http({
              method: 'POST',
              url: path, 
              data: data
            })
            .then(function (response) {
                deferred.resolve(data);
            }, 
            function (response) {
                deferred.reject(data);
            });

      return deferred.promise;

    }


  };
}
