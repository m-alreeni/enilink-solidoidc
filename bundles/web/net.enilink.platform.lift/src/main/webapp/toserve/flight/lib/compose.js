define(["./utils"],function(n){"use strict";function e(e,i){Object.create(null);Object.keys(e).forEach(function(r){t.indexOf(r)<0&&n.propertyWritability(e,r,i)})}function i(n,i){n.mixedIn=n.hasOwnProperty("mixedIn")?n.mixedIn:[];for(var t=0;t<i.length;t++)-1==n.mixedIn.indexOf(i[t])&&(e(n,!1),i[t].call(n),n.mixedIn.push(i[t]));e(n,!0)}var t=["mixedIn"];return{mixin:i}});