"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = {
  user: function user(state) {
    return state.user;
  },
  cognitoUser: function cognitoUser(state) {
    return state.cognitoUser;
  }
};