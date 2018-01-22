'use strict'

angular
    .module('auth', [])
    .factory('AuthenticationService', AuthenticationService)
    .factory('AuthorizationService', AuthorizationService)
    .directive('hasPermission', hasPermission)

/**
 * @name  hasPermission
 * @param AuthorizationService
 * @returns {{link: link}}
 */
function hasPermission (AuthorizationService) {
  return {
    link: function (scope, element, attrs) {
      if (typeof attrs.hasPermission !== 'string') {
        throw 'hasPermission value must be a string'
      }
      var value = attrs.hasPermission.trim()
      var notPermissionFlag = value[0] === '!'
      if (notPermissionFlag) {
        value = value.slice(1).trim()
      }

      function toggleVisibilityBasedOnPermission () {
        var hasPermission = AuthorizationService.hasPermission(value)
        if (hasPermission && !notPermissionFlag || !hasPermission && notPermissionFlag) {
          element.removeClass('ng-hide')
        } else {
          element.addClass('ng-hide')
        }
      }

      toggleVisibilityBasedOnPermission()
      scope.$on('permissionsChanged', toggleVisibilityBasedOnPermission)
    }
  }
}

/**
 * @name AuthenticationService
 * @param $cookies
 * @param $q
 * @param $http
 * @param AuthorizationService
 * @param $state
 * @param ENV
 * @returns {{checkToken: checkToken, login: login, getHeaders: getHeaders, logout: logout, getToken: getToken, getInit: getInit, setInit: setInit, setToken: setToken, removeToken: removeToken}}
 * @constructor
 */
function AuthenticationService ($cookies, $q, $http, AuthorizationService, $state, ENV, toaster, $location, $window) {
  var _initResponse

  var _tokenName = ENV.tokenName || '_token'
  var _loginState = ENV.loginState || 'login'
  var _homeState = ENV.homeState || 'dashboard'
  var _loginPath = ENV.apiCockpit.concat(ENV.loginPath || '/oauth/token')
  var _logoutPath = ENV.apiCockpit.concat(ENV.logoutPath || '/auth/logout')

  var removeToken = function () {
    $cookies.remove(_tokenName, {'domain': ENV.cookieHost})
    var referrerUrl = $location.$$path
    if (referrerUrl) {
      if (referrerUrl !== '/login') {
        $location.path('/login').search({referrer: referrerUrl})
      } else {
        $state.go(_loginState)
      }
    } else {
      $state.go(_homeState)
    }
  }

  var setToken = function (token) {
    $cookies.put(_tokenName, token, {'domain': ENV.cookieHost})
  }

  var getToken = function () {
    return $cookies.get(_tokenName, {'domain': ENV.cookieHost})
  }

  var removePermissionSignature = function () {
    AuthorizationService.removePermissionSignature()
  }

  var setInit = function (response) {
    AuthorizationService.setPermissions(response.user.positions.active.permissions)
    _initResponse = response
  }

  var removeInit = function () {
    _initResponse = null
  }

  var getInit = function () {
    return _initResponse
  }

  var getHeaders = function () {
    var _token = getToken()

    if (_token) {
      var obj = {'Authorization': 'Bearer ' + _token}
      return obj
    }
  }

  var logout = function () {
    return $http({
      method: 'POST',
      url: _logoutPath,
      headers: getHeaders()

    }).then(function (response) {
      removeToken()
      removeInit()
      removePermissionSignature()
    }, function (response) {

    })
  }

  var login = function (data) {
    var referrerUrl = $location.search().referrer

    return $http({
      method: 'POST',
      url: _loginPath,
      data: data
    }).then(function (response) {
      setToken(response.data.access_token)
      if (referrerUrl) {
        $location.path(referrerUrl).search({})
      } else {
        $state.go(_homeState)
      }
    }, function (error) {
      if (error.status === 401) {
        toaster.pop('error', 'Whoops!', error.data.message)
      }
    })
  }

  var checkToken = function () {
    if (typeof getToken() !== 'undefined') {
      $state.go(_homeState)
    }
  }

  return {
    checkToken: checkToken,
    login: login,
    getHeaders: getHeaders,
    logout: logout,
    getToken: getToken,
    getInit: getInit,
    setInit: setInit,
    setToken: setToken,
    removeToken: removeToken
  }
}

/**
 * @name AuthorizationService
 * @param $rootScope
 * @returns {{setPermissions: setPermissions, hasPermission: hasPermission}}
 * @constructor
 */
function AuthorizationService ($rootScope) {
  var permissionList
  var permissionSignature

  return {
    setPermissions: function (permissions) {
      permissionList = permissions
      $rootScope.$broadcast('permissionsChanged')
    },
    hasPermission: function (permission) {
      permission = permission.trim()
      return permissionList[permission]
    },
    setPermissionSignature: function (signature) {
      permissionSignature = signature
    },
    getPermissionSignature: function () {
      return permissionSignature
    },
    removePermissionSignature: function () {
      permissionSignature = null
    }
  }
}
