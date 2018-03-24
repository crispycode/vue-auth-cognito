'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _actions = require('./actions');

var _actions2 = _interopRequireDefault(_actions);

var _mutations = require('./mutations');

var _mutations2 = _interopRequireDefault(_mutations);

var _getters = require('./getters');

var _getters2 = _interopRequireDefault(_getters);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var state = {
  user: null,
  cognitoUser: null
};

// Example state
// const state = {
//   user: {
//     username: 'username in any format: email, UUID, etc.',
//     tokens: null | {
//       IdToken: '', // in JWT format
//       RefreshToken: '', // in JWT format
//       AccessToken: '', // in JWT format
//     },
//     attributes: {
//       email: 'user email',
//       phone_number: '+1 555 12345',
//       ...
//     }
//   },
// };

var CognitoAuth = function CognitoAuth(config) {
  _classCallCheck(this, CognitoAuth);

  this.state = state;
  this.actions = new _actions2.default(config);
  this.mutations = _mutations2.default;
  this.getters = _getters2.default;
};

exports.default = CognitoAuth;