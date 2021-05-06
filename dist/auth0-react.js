(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined'
    ? factory(exports, require('react'))
    : typeof define === 'function' && define.amd
    ? define(['exports', 'react'], factory)
    : ((global = global || self),
      factory((global.reactAuth0 = {}), global.React));
})(this, function (exports, React) {
  'use strict';

  var React__default = 'default' in React ? React['default'] : React;

  /*! *****************************************************************************
    Copyright (c) Microsoft Corporation. All rights reserved.
    Licensed under the Apache License, Version 2.0 (the "License"); you may not use
    this file except in compliance with the License. You may obtain a copy of the
    License at http://www.apache.org/licenses/LICENSE-2.0

    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
    WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
    MERCHANTABLITY OR NON-INFRINGEMENT.

    See the Apache Version 2.0 License for specific language governing permissions
    and limitations under the License.
    ***************************************************************************** */
  /* global Reflect, Promise */

  var extendStatics = function (d, b) {
    extendStatics =
      Object.setPrototypeOf ||
      ({ __proto__: [] } instanceof Array &&
        function (d, b) {
          d.__proto__ = b;
        }) ||
      function (d, b) {
        for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p];
      };
    return extendStatics(d, b);
  };

  function __extends(d, b) {
    extendStatics(d, b);
    function __() {
      this.constructor = d;
    }
    d.prototype =
      b === null ? Object.create(b) : ((__.prototype = b.prototype), new __());
  }

  var __assign = function () {
    __assign =
      Object.assign ||
      function __assign(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
          s = arguments[i];
          for (var p in s)
            if (Object.prototype.hasOwnProperty.call(s, p)) t[p] = s[p];
        }
        return t;
      };
    return __assign.apply(this, arguments);
  };

  function __rest(s, e) {
    var t = {};
    for (var p in s)
      if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === 'function')
      for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
        if (
          e.indexOf(p[i]) < 0 &&
          Object.prototype.propertyIsEnumerable.call(s, p[i])
        )
          t[p[i]] = s[p[i]];
      }
    return t;
  }

  function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) {
      return value instanceof P
        ? value
        : new P(function (resolve) {
            resolve(value);
          });
    }
    return new (P || (P = Promise))(function (resolve, reject) {
      function fulfilled(value) {
        try {
          step(generator.next(value));
        } catch (e) {
          reject(e);
        }
      }
      function rejected(value) {
        try {
          step(generator['throw'](value));
        } catch (e) {
          reject(e);
        }
      }
      function step(result) {
        result.done
          ? resolve(result.value)
          : adopt(result.value).then(fulfilled, rejected);
      }
      step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
  }

  function __generator(thisArg, body) {
    var _ = {
        label: 0,
        sent: function () {
          if (t[0] & 1) throw t[1];
          return t[1];
        },
        trys: [],
        ops: [],
      },
      f,
      y,
      t,
      g;
    return (
      (g = { next: verb(0), throw: verb(1), return: verb(2) }),
      typeof Symbol === 'function' &&
        (g[Symbol.iterator] = function () {
          return this;
        }),
      g
    );
    function verb(n) {
      return function (v) {
        return step([n, v]);
      };
    }
    function step(op) {
      if (f) throw new TypeError('Generator is already executing.');
      while (_)
        try {
          if (
            ((f = 1),
            y &&
              (t =
                op[0] & 2
                  ? y['return']
                  : op[0]
                  ? y['throw'] || ((t = y['return']) && t.call(y), 0)
                  : y.next) &&
              !(t = t.call(y, op[1])).done)
          )
            return t;
          if (((y = 0), t)) op = [op[0] & 2, t.value];
          switch (op[0]) {
            case 0:
            case 1:
              t = op;
              break;
            case 4:
              _.label++;
              return { value: op[1], done: false };
            case 5:
              _.label++;
              y = op[1];
              op = [0];
              continue;
            case 7:
              op = _.ops.pop();
              _.trys.pop();
              continue;
            default:
              if (
                !((t = _.trys), (t = t.length > 0 && t[t.length - 1])) &&
                (op[0] === 6 || op[0] === 2)
              ) {
                _ = 0;
                continue;
              }
              if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) {
                _.label = op[1];
                break;
              }
              if (op[0] === 6 && _.label < t[1]) {
                _.label = t[1];
                t = op;
                break;
              }
              if (t && _.label < t[2]) {
                _.label = t[2];
                _.ops.push(op);
                break;
              }
              if (t[2]) _.ops.pop();
              _.trys.pop();
              continue;
          }
          op = body.call(thisArg, _);
        } catch (e) {
          op = [6, e];
          y = 0;
        } finally {
          f = t = 0;
        }
      if (op[0] & 5) throw op[1];
      return { value: op[0] ? op[1] : void 0, done: true };
    }
  }

  /*! *****************************************************************************
    Copyright (c) Microsoft Corporation.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
    REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
    INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
    LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
    OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.
    ***************************************************************************** */
  var e = function (t, n) {
    return (e =
      Object.setPrototypeOf ||
      ({ __proto__: [] } instanceof Array &&
        function (e, t) {
          e.__proto__ = t;
        }) ||
      function (e, t) {
        for (var n in t)
          Object.prototype.hasOwnProperty.call(t, n) && (e[n] = t[n]);
      })(t, n);
  };
  function t(t, n) {
    if ('function' != typeof n && null !== n)
      throw new TypeError(
        'Class extends value ' + String(n) + ' is not a constructor or null'
      );
    function r() {
      this.constructor = t;
    }
    e(t, n),
      (t.prototype =
        null === n ? Object.create(n) : ((r.prototype = n.prototype), new r()));
  }
  var n = function () {
    return (n =
      Object.assign ||
      function (e) {
        for (var t, n = 1, r = arguments.length; n < r; n++)
          for (var o in (t = arguments[n]))
            Object.prototype.hasOwnProperty.call(t, o) && (e[o] = t[o]);
        return e;
      }).apply(this, arguments);
  };
  function r(e, t) {
    var n = {};
    for (var r in e)
      Object.prototype.hasOwnProperty.call(e, r) &&
        t.indexOf(r) < 0 &&
        (n[r] = e[r]);
    if (null != e && 'function' == typeof Object.getOwnPropertySymbols) {
      var o = 0;
      for (r = Object.getOwnPropertySymbols(e); o < r.length; o++)
        t.indexOf(r[o]) < 0 &&
          Object.prototype.propertyIsEnumerable.call(e, r[o]) &&
          (n[r[o]] = e[r[o]]);
    }
    return n;
  }
  function o(e, t, n, r) {
    return new (n || (n = Promise))(function (o, i) {
      function a(e) {
        try {
          s(r.next(e));
        } catch (e) {
          i(e);
        }
      }
      function c(e) {
        try {
          s(r.throw(e));
        } catch (e) {
          i(e);
        }
      }
      function s(e) {
        var t;
        e.done
          ? o(e.value)
          : ((t = e.value),
            t instanceof n
              ? t
              : new n(function (e) {
                  e(t);
                })).then(a, c);
      }
      s((r = r.apply(e, t || [])).next());
    });
  }
  function i(e, t) {
    var n,
      r,
      o,
      i,
      a = {
        label: 0,
        sent: function () {
          if (1 & o[0]) throw o[1];
          return o[1];
        },
        trys: [],
        ops: [],
      };
    return (
      (i = { next: c(0), throw: c(1), return: c(2) }),
      'function' == typeof Symbol &&
        (i[Symbol.iterator] = function () {
          return this;
        }),
      i
    );
    function c(i) {
      return function (c) {
        return (function (i) {
          if (n) throw new TypeError('Generator is already executing.');
          for (; a; )
            try {
              if (
                ((n = 1),
                r &&
                  (o =
                    2 & i[0]
                      ? r.return
                      : i[0]
                      ? r.throw || ((o = r.return) && o.call(r), 0)
                      : r.next) &&
                  !(o = o.call(r, i[1])).done)
              )
                return o;
              switch (((r = 0), o && (i = [2 & i[0], o.value]), i[0])) {
                case 0:
                case 1:
                  o = i;
                  break;
                case 4:
                  return a.label++, { value: i[1], done: !1 };
                case 5:
                  a.label++, (r = i[1]), (i = [0]);
                  continue;
                case 7:
                  (i = a.ops.pop()), a.trys.pop();
                  continue;
                default:
                  if (
                    !((o = a.trys),
                    (o = o.length > 0 && o[o.length - 1]) ||
                      (6 !== i[0] && 2 !== i[0]))
                  ) {
                    a = 0;
                    continue;
                  }
                  if (3 === i[0] && (!o || (i[1] > o[0] && i[1] < o[3]))) {
                    a.label = i[1];
                    break;
                  }
                  if (6 === i[0] && a.label < o[1]) {
                    (a.label = o[1]), (o = i);
                    break;
                  }
                  if (o && a.label < o[2]) {
                    (a.label = o[2]), a.ops.push(i);
                    break;
                  }
                  o[2] && a.ops.pop(), a.trys.pop();
                  continue;
              }
              i = t.call(e, a);
            } catch (e) {
              (i = [6, e]), (r = 0);
            } finally {
              n = o = 0;
            }
          if (5 & i[0]) throw i[1];
          return { value: i[0] ? i[1] : void 0, done: !0 };
        })([i, c]);
      };
    }
  }
  var a =
    'undefined' != typeof globalThis
      ? globalThis
      : 'undefined' != typeof window
      ? window
      : 'undefined' != typeof global
      ? global
      : 'undefined' != typeof self
      ? self
      : {};
  function c(e) {
    return e &&
      e.__esModule &&
      Object.prototype.hasOwnProperty.call(e, 'default')
      ? e.default
      : e;
  }
  function s(e, t) {
    return e((t = { exports: {} }), t.exports), t.exports;
  }
  var u = function (e) {
      return e && e.Math == Math && e;
    },
    l =
      u('object' == typeof globalThis && globalThis) ||
      u('object' == typeof window && window) ||
      u('object' == typeof self && self) ||
      u('object' == typeof a && a) ||
      (function () {
        return this;
      })() ||
      Function('return this')(),
    f = function (e) {
      try {
        return !!e();
      } catch (e) {
        return !0;
      }
    },
    d = !f(function () {
      return (
        7 !=
        Object.defineProperty({}, 1, {
          get: function () {
            return 7;
          },
        })[1]
      );
    }),
    p = {}.propertyIsEnumerable,
    h = Object.getOwnPropertyDescriptor,
    y = {
      f:
        h && !p.call({ 1: 2 }, 1)
          ? function (e) {
              var t = h(this, e);
              return !!t && t.enumerable;
            }
          : p,
    },
    v = function (e, t) {
      return {
        enumerable: !(1 & e),
        configurable: !(2 & e),
        writable: !(4 & e),
        value: t,
      };
    },
    m = {}.toString,
    g = function (e) {
      return m.call(e).slice(8, -1);
    },
    b = ''.split,
    w = f(function () {
      return !Object('z').propertyIsEnumerable(0);
    })
      ? function (e) {
          return 'String' == g(e) ? b.call(e, '') : Object(e);
        }
      : Object,
    S = function (e) {
      if (null == e) throw TypeError("Can't call method on " + e);
      return e;
    },
    _ = function (e) {
      return w(S(e));
    },
    k = function (e) {
      return 'object' == typeof e ? null !== e : 'function' == typeof e;
    },
    I = function (e, t) {
      if (!k(e)) return e;
      var n, r;
      if (t && 'function' == typeof (n = e.toString) && !k((r = n.call(e))))
        return r;
      if ('function' == typeof (n = e.valueOf) && !k((r = n.call(e)))) return r;
      if (!t && 'function' == typeof (n = e.toString) && !k((r = n.call(e))))
        return r;
      throw TypeError("Can't convert object to primitive value");
    },
    T = function (e) {
      return Object(S(e));
    },
    O = {}.hasOwnProperty,
    E = function (e, t) {
      return O.call(T(e), t);
    },
    x = l.document,
    R = k(x) && k(x.createElement),
    L = function (e) {
      return R ? x.createElement(e) : {};
    },
    C =
      !d &&
      !f(function () {
        return (
          7 !=
          Object.defineProperty(L('div'), 'a', {
            get: function () {
              return 7;
            },
          }).a
        );
      }),
    j = Object.getOwnPropertyDescriptor,
    U = {
      f: d
        ? j
        : function (e, t) {
            if (((e = _(e)), (t = I(t, !0)), C))
              try {
                return j(e, t);
              } catch (e) {}
            if (E(e, t)) return v(!y.f.call(e, t), e[t]);
          },
    },
    A = function (e) {
      if (!k(e)) throw TypeError(String(e) + ' is not an object');
      return e;
    },
    P = Object.defineProperty,
    F = {
      f: d
        ? P
        : function (e, t, n) {
            if ((A(e), (t = I(t, !0)), A(n), C))
              try {
                return P(e, t, n);
              } catch (e) {}
            if ('get' in n || 'set' in n)
              throw TypeError('Accessors not supported');
            return 'value' in n && (e[t] = n.value), e;
          },
    },
    K = d
      ? function (e, t, n) {
          return F.f(e, t, v(1, n));
        }
      : function (e, t, n) {
          return (e[t] = n), e;
        },
    W = function (e, t) {
      try {
        K(l, e, t);
      } catch (n) {
        l[e] = t;
      }
      return t;
    },
    z = l['__core-js_shared__'] || W('__core-js_shared__', {}),
    V = Function.toString;
  'function' != typeof z.inspectSource &&
    (z.inspectSource = function (e) {
      return V.call(e);
    });
  var Z,
    X,
    N,
    G = z.inspectSource,
    J = l.WeakMap,
    D = 'function' == typeof J && /native code/.test(G(J)),
    Y = s(function (e) {
      (e.exports = function (e, t) {
        return z[e] || (z[e] = void 0 !== t ? t : {});
      })('versions', []).push({
        version: '3.11.0',
        mode: 'global',
        copyright: '© 2021 Denis Pushkarev (zloirock.ru)',
      });
    }),
    B = 0,
    M = Math.random(),
    q = function (e) {
      return (
        'Symbol(' +
        String(void 0 === e ? '' : e) +
        ')_' +
        (++B + M).toString(36)
      );
    },
    H = Y('keys'),
    Q = function (e) {
      return H[e] || (H[e] = q(e));
    },
    $ = {},
    ee = l.WeakMap;
  if (D) {
    var te = z.state || (z.state = new ee()),
      ne = te.get,
      re = te.has,
      oe = te.set;
    (Z = function (e, t) {
      if (re.call(te, e)) throw new TypeError('Object already initialized');
      return (t.facade = e), oe.call(te, e, t), t;
    }),
      (X = function (e) {
        return ne.call(te, e) || {};
      }),
      (N = function (e) {
        return re.call(te, e);
      });
  } else {
    var ie = Q('state');
    ($[ie] = !0),
      (Z = function (e, t) {
        if (E(e, ie)) throw new TypeError('Object already initialized');
        return (t.facade = e), K(e, ie, t), t;
      }),
      (X = function (e) {
        return E(e, ie) ? e[ie] : {};
      }),
      (N = function (e) {
        return E(e, ie);
      });
  }
  var ae,
    ce,
    se = {
      set: Z,
      get: X,
      has: N,
      enforce: function (e) {
        return N(e) ? X(e) : Z(e, {});
      },
      getterFor: function (e) {
        return function (t) {
          var n;
          if (!k(t) || (n = X(t)).type !== e)
            throw TypeError('Incompatible receiver, ' + e + ' required');
          return n;
        };
      },
    },
    ue = s(function (e) {
      var t = se.get,
        n = se.enforce,
        r = String(String).split('String');
      (e.exports = function (e, t, o, i) {
        var a,
          c = !!i && !!i.unsafe,
          s = !!i && !!i.enumerable,
          u = !!i && !!i.noTargetGet;
        'function' == typeof o &&
          ('string' != typeof t || E(o, 'name') || K(o, 'name', t),
          (a = n(o)).source ||
            (a.source = r.join('string' == typeof t ? t : ''))),
          e !== l
            ? (c ? !u && e[t] && (s = !0) : delete e[t],
              s ? (e[t] = o) : K(e, t, o))
            : s
            ? (e[t] = o)
            : W(t, o);
      })(Function.prototype, 'toString', function () {
        return ('function' == typeof this && t(this).source) || G(this);
      });
    }),
    le = l,
    fe = function (e) {
      return 'function' == typeof e ? e : void 0;
    },
    de = function (e, t) {
      return arguments.length < 2
        ? fe(le[e]) || fe(l[e])
        : (le[e] && le[e][t]) || (l[e] && l[e][t]);
    },
    pe = Math.ceil,
    he = Math.floor,
    ye = function (e) {
      return isNaN((e = +e)) ? 0 : (e > 0 ? he : pe)(e);
    },
    ve = Math.min,
    me = function (e) {
      return e > 0 ? ve(ye(e), 9007199254740991) : 0;
    },
    ge = Math.max,
    be = Math.min,
    we = function (e) {
      return function (t, n, r) {
        var o,
          i = _(t),
          a = me(i.length),
          c = (function (e, t) {
            var n = ye(e);
            return n < 0 ? ge(n + t, 0) : be(n, t);
          })(r, a);
        if (e && n != n) {
          for (; a > c; ) if ((o = i[c++]) != o) return !0;
        } else
          for (; a > c; c++)
            if ((e || c in i) && i[c] === n) return e || c || 0;
        return !e && -1;
      };
    },
    Se = { includes: we(!0), indexOf: we(!1) },
    _e = Se.indexOf,
    ke = function (e, t) {
      var n,
        r = _(e),
        o = 0,
        i = [];
      for (n in r) !E($, n) && E(r, n) && i.push(n);
      for (; t.length > o; ) E(r, (n = t[o++])) && (~_e(i, n) || i.push(n));
      return i;
    },
    Ie = [
      'constructor',
      'hasOwnProperty',
      'isPrototypeOf',
      'propertyIsEnumerable',
      'toLocaleString',
      'toString',
      'valueOf',
    ],
    Te = Ie.concat('length', 'prototype'),
    Oe = {
      f:
        Object.getOwnPropertyNames ||
        function (e) {
          return ke(e, Te);
        },
    },
    Ee = { f: Object.getOwnPropertySymbols },
    xe =
      de('Reflect', 'ownKeys') ||
      function (e) {
        var t = Oe.f(A(e)),
          n = Ee.f;
        return n ? t.concat(n(e)) : t;
      },
    Re = function (e, t) {
      for (var n = xe(t), r = F.f, o = U.f, i = 0; i < n.length; i++) {
        var a = n[i];
        E(e, a) || r(e, a, o(t, a));
      }
    },
    Le = /#|\.prototype\./,
    Ce = function (e, t) {
      var n = Ue[je(e)];
      return n == Pe || (n != Ae && ('function' == typeof t ? f(t) : !!t));
    },
    je = (Ce.normalize = function (e) {
      return String(e).replace(Le, '.').toLowerCase();
    }),
    Ue = (Ce.data = {}),
    Ae = (Ce.NATIVE = 'N'),
    Pe = (Ce.POLYFILL = 'P'),
    Fe = Ce,
    Ke = U.f,
    We = function (e, t) {
      var n,
        r,
        o,
        i,
        a,
        c = e.target,
        s = e.global,
        u = e.stat;
      if ((n = s ? l : u ? l[c] || W(c, {}) : (l[c] || {}).prototype))
        for (r in t) {
          if (
            ((i = t[r]),
            (o = e.noTargetGet ? (a = Ke(n, r)) && a.value : n[r]),
            !Fe(s ? r : c + (u ? '.' : '#') + r, e.forced) && void 0 !== o)
          ) {
            if (typeof i == typeof o) continue;
            Re(i, o);
          }
          (e.sham || (o && o.sham)) && K(i, 'sham', !0), ue(n, r, i, e);
        }
    },
    ze = 'process' == g(l.process),
    Ve = de('navigator', 'userAgent') || '',
    Ze = l.process,
    Xe = Ze && Ze.versions,
    Ne = Xe && Xe.v8;
  Ne
    ? (ce = (ae = Ne.split('.'))[0] + ae[1])
    : Ve &&
      (!(ae = Ve.match(/Edge\/(\d+)/)) || ae[1] >= 74) &&
      (ae = Ve.match(/Chrome\/(\d+)/)) &&
      (ce = ae[1]);
  var Ge,
    Je = ce && +ce,
    De =
      !!Object.getOwnPropertySymbols &&
      !f(function () {
        return !Symbol.sham && (ze ? 38 === Je : Je > 37 && Je < 41);
      }),
    Ye = De && !Symbol.sham && 'symbol' == typeof Symbol.iterator,
    Be = Y('wks'),
    Me = l.Symbol,
    qe = Ye ? Me : (Me && Me.withoutSetter) || q,
    He = function (e) {
      return (
        (E(Be, e) && (De || 'string' == typeof Be[e])) ||
          (De && E(Me, e) ? (Be[e] = Me[e]) : (Be[e] = qe('Symbol.' + e))),
        Be[e]
      );
    },
    Qe = He('match'),
    $e = function (e) {
      if (
        (function (e) {
          var t;
          return k(e) && (void 0 !== (t = e[Qe]) ? !!t : 'RegExp' == g(e));
        })(e)
      )
        throw TypeError("The method doesn't accept regular expressions");
      return e;
    },
    et = He('match'),
    tt = function (e) {
      var t = /./;
      try {
        '/./'[e](t);
      } catch (n) {
        try {
          return (t[et] = !1), '/./'[e](t);
        } catch (e) {}
      }
      return !1;
    },
    nt = U.f,
    rt = ''.startsWith,
    ot = Math.min,
    it = tt('startsWith'),
    at = !(
      it || ((Ge = nt(String.prototype, 'startsWith')), !Ge || Ge.writable)
    );
  We(
    { target: 'String', proto: !0, forced: !at && !it },
    {
      startsWith: function (e) {
        var t = String(S(this));
        $e(e);
        var n = me(ot(arguments.length > 1 ? arguments[1] : void 0, t.length)),
          r = String(e);
        return rt ? rt.call(t, r, n) : t.slice(n, n + r.length) === r;
      },
    }
  );
  var ct = function (e) {
      if ('function' != typeof e)
        throw TypeError(String(e) + ' is not a function');
      return e;
    },
    st = function (e, t, n) {
      if ((ct(e), void 0 === t)) return e;
      switch (n) {
        case 0:
          return function () {
            return e.call(t);
          };
        case 1:
          return function (n) {
            return e.call(t, n);
          };
        case 2:
          return function (n, r) {
            return e.call(t, n, r);
          };
        case 3:
          return function (n, r, o) {
            return e.call(t, n, r, o);
          };
      }
      return function () {
        return e.apply(t, arguments);
      };
    },
    ut = Function.call,
    lt = function (e, t, n) {
      return st(ut, l[e].prototype[t], n);
    };
  lt('String', 'startsWith');
  var ft =
      Array.isArray ||
      function (e) {
        return 'Array' == g(e);
      },
    dt = function (e, t, n) {
      var r = I(t);
      r in e ? F.f(e, r, v(0, n)) : (e[r] = n);
    },
    pt = He('species'),
    ht = function (e, t) {
      var n;
      return (
        ft(e) &&
          ('function' != typeof (n = e.constructor) ||
          (n !== Array && !ft(n.prototype))
            ? k(n) && null === (n = n[pt]) && (n = void 0)
            : (n = void 0)),
        new (void 0 === n ? Array : n)(0 === t ? 0 : t)
      );
    },
    yt = He('species'),
    vt = He('isConcatSpreadable'),
    mt =
      Je >= 51 ||
      !f(function () {
        var e = [];
        return (e[vt] = !1), e.concat()[0] !== e;
      }),
    gt = (function (e) {
      return (
        Je >= 51 ||
        !f(function () {
          var t = [];
          return (
            ((t.constructor = {})[yt] = function () {
              return { foo: 1 };
            }),
            1 !== t[e](Boolean).foo
          );
        })
      );
    })('concat'),
    bt = function (e) {
      if (!k(e)) return !1;
      var t = e[vt];
      return void 0 !== t ? !!t : ft(e);
    };
  We(
    { target: 'Array', proto: !0, forced: !mt || !gt },
    {
      concat: function (e) {
        var t,
          n,
          r,
          o,
          i,
          a = T(this),
          c = ht(a, 0),
          s = 0;
        for (t = -1, r = arguments.length; t < r; t++)
          if (bt((i = -1 === t ? a : arguments[t]))) {
            if (s + (o = me(i.length)) > 9007199254740991)
              throw TypeError('Maximum allowed index exceeded');
            for (n = 0; n < o; n++, s++) n in i && dt(c, s, i[n]);
          } else {
            if (s >= 9007199254740991)
              throw TypeError('Maximum allowed index exceeded');
            dt(c, s++, i);
          }
        return (c.length = s), c;
      },
    }
  );
  var wt = {};
  wt[He('toStringTag')] = 'z';
  var St = '[object z]' === String(wt),
    _t = He('toStringTag'),
    kt =
      'Arguments' ==
      g(
        (function () {
          return arguments;
        })()
      ),
    It = St
      ? g
      : function (e) {
          var t, n, r;
          return void 0 === e
            ? 'Undefined'
            : null === e
            ? 'Null'
            : 'string' ==
              typeof (n = (function (e, t) {
                try {
                  return e[t];
                } catch (e) {}
              })((t = Object(e)), _t))
            ? n
            : kt
            ? g(t)
            : 'Object' == (r = g(t)) && 'function' == typeof t.callee
            ? 'Arguments'
            : r;
        },
    Tt = St
      ? {}.toString
      : function () {
          return '[object ' + It(this) + ']';
        };
  St || ue(Object.prototype, 'toString', Tt, { unsafe: !0 });
  var Ot,
    Et =
      Object.keys ||
      function (e) {
        return ke(e, Ie);
      },
    xt = d
      ? Object.defineProperties
      : function (e, t) {
          A(e);
          for (var n, r = Et(t), o = r.length, i = 0; o > i; )
            F.f(e, (n = r[i++]), t[n]);
          return e;
        },
    Rt = de('document', 'documentElement'),
    Lt = Q('IE_PROTO'),
    Ct = function () {},
    jt = function (e) {
      return '<script>' + e + '</script>';
    },
    Ut = function () {
      try {
        Ot = document.domain && new ActiveXObject('htmlfile');
      } catch (e) {}
      var e, t;
      Ut = Ot
        ? (function (e) {
            e.write(jt('')), e.close();
            var t = e.parentWindow.Object;
            return (e = null), t;
          })(Ot)
        : (((t = L('iframe')).style.display = 'none'),
          Rt.appendChild(t),
          (t.src = String('javascript:')),
          (e = t.contentWindow.document).open(),
          e.write(jt('document.F=Object')),
          e.close(),
          e.F);
      for (var n = Ie.length; n--; ) delete Ut.prototype[Ie[n]];
      return Ut();
    };
  $[Lt] = !0;
  var At =
      Object.create ||
      function (e, t) {
        var n;
        return (
          null !== e
            ? ((Ct.prototype = A(e)),
              (n = new Ct()),
              (Ct.prototype = null),
              (n[Lt] = e))
            : (n = Ut()),
          void 0 === t ? n : xt(n, t)
        );
      },
    Pt = Oe.f,
    Ft = {}.toString,
    Kt =
      'object' == typeof window && window && Object.getOwnPropertyNames
        ? Object.getOwnPropertyNames(window)
        : [],
    Wt = {
      f: function (e) {
        return Kt && '[object Window]' == Ft.call(e)
          ? (function (e) {
              try {
                return Pt(e);
              } catch (e) {
                return Kt.slice();
              }
            })(e)
          : Pt(_(e));
      },
    },
    zt = { f: He },
    Vt = F.f,
    Zt = function (e) {
      var t = le.Symbol || (le.Symbol = {});
      E(t, e) || Vt(t, e, { value: zt.f(e) });
    },
    Xt = F.f,
    Nt = He('toStringTag'),
    Gt = function (e, t, n) {
      e &&
        !E((e = n ? e : e.prototype), Nt) &&
        Xt(e, Nt, { configurable: !0, value: t });
    },
    Jt = [].push,
    Dt = function (e) {
      var t = 1 == e,
        n = 2 == e,
        r = 3 == e,
        o = 4 == e,
        i = 6 == e,
        a = 7 == e,
        c = 5 == e || i;
      return function (s, u, l, f) {
        for (
          var d,
            p,
            h = T(s),
            y = w(h),
            v = st(u, l, 3),
            m = me(y.length),
            g = 0,
            b = f || ht,
            S = t ? b(s, m) : n || a ? b(s, 0) : void 0;
          m > g;
          g++
        )
          if ((c || g in y) && ((p = v((d = y[g]), g, h)), e))
            if (t) S[g] = p;
            else if (p)
              switch (e) {
                case 3:
                  return !0;
                case 5:
                  return d;
                case 6:
                  return g;
                case 2:
                  Jt.call(S, d);
              }
            else
              switch (e) {
                case 4:
                  return !1;
                case 7:
                  Jt.call(S, d);
              }
        return i ? -1 : r || o ? o : S;
      };
    },
    Yt = {
      forEach: Dt(0),
      map: Dt(1),
      filter: Dt(2),
      some: Dt(3),
      every: Dt(4),
      find: Dt(5),
      findIndex: Dt(6),
      filterOut: Dt(7),
    }.forEach,
    Bt = Q('hidden'),
    Mt = He('toPrimitive'),
    qt = se.set,
    Ht = se.getterFor('Symbol'),
    Qt = Object.prototype,
    $t = l.Symbol,
    en = de('JSON', 'stringify'),
    tn = U.f,
    nn = F.f,
    rn = Wt.f,
    on = y.f,
    an = Y('symbols'),
    cn = Y('op-symbols'),
    sn = Y('string-to-symbol-registry'),
    un = Y('symbol-to-string-registry'),
    ln = Y('wks'),
    fn = l.QObject,
    dn = !fn || !fn.prototype || !fn.prototype.findChild,
    pn =
      d &&
      f(function () {
        return (
          7 !=
          At(
            nn({}, 'a', {
              get: function () {
                return nn(this, 'a', { value: 7 }).a;
              },
            })
          ).a
        );
      })
        ? function (e, t, n) {
            var r = tn(Qt, t);
            r && delete Qt[t], nn(e, t, n), r && e !== Qt && nn(Qt, t, r);
          }
        : nn,
    hn = function (e, t) {
      var n = (an[e] = At($t.prototype));
      return (
        qt(n, { type: 'Symbol', tag: e, description: t }),
        d || (n.description = t),
        n
      );
    },
    yn = Ye
      ? function (e) {
          return 'symbol' == typeof e;
        }
      : function (e) {
          return Object(e) instanceof $t;
        },
    vn = function (e, t, n) {
      e === Qt && vn(cn, t, n), A(e);
      var r = I(t, !0);
      return (
        A(n),
        E(an, r)
          ? (n.enumerable
              ? (E(e, Bt) && e[Bt][r] && (e[Bt][r] = !1),
                (n = At(n, { enumerable: v(0, !1) })))
              : (E(e, Bt) || nn(e, Bt, v(1, {})), (e[Bt][r] = !0)),
            pn(e, r, n))
          : nn(e, r, n)
      );
    },
    mn = function (e, t) {
      A(e);
      var n = _(t),
        r = Et(n).concat(Sn(n));
      return (
        Yt(r, function (t) {
          (d && !gn.call(n, t)) || vn(e, t, n[t]);
        }),
        e
      );
    },
    gn = function (e) {
      var t = I(e, !0),
        n = on.call(this, t);
      return (
        !(this === Qt && E(an, t) && !E(cn, t)) &&
        (!(n || !E(this, t) || !E(an, t) || (E(this, Bt) && this[Bt][t])) || n)
      );
    },
    bn = function (e, t) {
      var n = _(e),
        r = I(t, !0);
      if (n !== Qt || !E(an, r) || E(cn, r)) {
        var o = tn(n, r);
        return (
          !o || !E(an, r) || (E(n, Bt) && n[Bt][r]) || (o.enumerable = !0), o
        );
      }
    },
    wn = function (e) {
      var t = rn(_(e)),
        n = [];
      return (
        Yt(t, function (e) {
          E(an, e) || E($, e) || n.push(e);
        }),
        n
      );
    },
    Sn = function (e) {
      var t = e === Qt,
        n = rn(t ? cn : _(e)),
        r = [];
      return (
        Yt(n, function (e) {
          !E(an, e) || (t && !E(Qt, e)) || r.push(an[e]);
        }),
        r
      );
    };
  if (
    (De ||
      (ue(
        ($t = function () {
          if (this instanceof $t)
            throw TypeError('Symbol is not a constructor');
          var e =
              arguments.length && void 0 !== arguments[0]
                ? String(arguments[0])
                : void 0,
            t = q(e),
            n = function (e) {
              this === Qt && n.call(cn, e),
                E(this, Bt) && E(this[Bt], t) && (this[Bt][t] = !1),
                pn(this, t, v(1, e));
            };
          return d && dn && pn(Qt, t, { configurable: !0, set: n }), hn(t, e);
        }).prototype,
        'toString',
        function () {
          return Ht(this).tag;
        }
      ),
      ue($t, 'withoutSetter', function (e) {
        return hn(q(e), e);
      }),
      (y.f = gn),
      (F.f = vn),
      (U.f = bn),
      (Oe.f = Wt.f = wn),
      (Ee.f = Sn),
      (zt.f = function (e) {
        return hn(He(e), e);
      }),
      d &&
        (nn($t.prototype, 'description', {
          configurable: !0,
          get: function () {
            return Ht(this).description;
          },
        }),
        ue(Qt, 'propertyIsEnumerable', gn, { unsafe: !0 }))),
    We({ global: !0, wrap: !0, forced: !De, sham: !De }, { Symbol: $t }),
    Yt(Et(ln), function (e) {
      Zt(e);
    }),
    We(
      { target: 'Symbol', stat: !0, forced: !De },
      {
        for: function (e) {
          var t = String(e);
          if (E(sn, t)) return sn[t];
          var n = $t(t);
          return (sn[t] = n), (un[n] = t), n;
        },
        keyFor: function (e) {
          if (!yn(e)) throw TypeError(e + ' is not a symbol');
          if (E(un, e)) return un[e];
        },
        useSetter: function () {
          dn = !0;
        },
        useSimple: function () {
          dn = !1;
        },
      }
    ),
    We(
      { target: 'Object', stat: !0, forced: !De, sham: !d },
      {
        create: function (e, t) {
          return void 0 === t ? At(e) : mn(At(e), t);
        },
        defineProperty: vn,
        defineProperties: mn,
        getOwnPropertyDescriptor: bn,
      }
    ),
    We(
      { target: 'Object', stat: !0, forced: !De },
      { getOwnPropertyNames: wn, getOwnPropertySymbols: Sn }
    ),
    We(
      {
        target: 'Object',
        stat: !0,
        forced: f(function () {
          Ee.f(1);
        }),
      },
      {
        getOwnPropertySymbols: function (e) {
          return Ee.f(T(e));
        },
      }
    ),
    en)
  ) {
    var _n =
      !De ||
      f(function () {
        var e = $t();
        return (
          '[null]' != en([e]) || '{}' != en({ a: e }) || '{}' != en(Object(e))
        );
      });
    We(
      { target: 'JSON', stat: !0, forced: _n },
      {
        stringify: function (e, t, n) {
          for (var r, o = [e], i = 1; arguments.length > i; )
            o.push(arguments[i++]);
          if (((r = t), (k(t) || void 0 !== e) && !yn(e)))
            return (
              ft(t) ||
                (t = function (e, t) {
                  if (
                    ('function' == typeof r && (t = r.call(this, e, t)), !yn(t))
                  )
                    return t;
                }),
              (o[1] = t),
              en.apply(null, o)
            );
        },
      }
    );
  }
  $t.prototype[Mt] || K($t.prototype, Mt, $t.prototype.valueOf),
    Gt($t, 'Symbol'),
    ($[Bt] = !0),
    Zt('asyncIterator');
  var kn = F.f,
    In = l.Symbol;
  if (
    d &&
    'function' == typeof In &&
    (!('description' in In.prototype) || void 0 !== In().description)
  ) {
    var Tn = {},
      On = function () {
        var e =
            arguments.length < 1 || void 0 === arguments[0]
              ? void 0
              : String(arguments[0]),
          t = this instanceof On ? new In(e) : void 0 === e ? In() : In(e);
        return '' === e && (Tn[t] = !0), t;
      };
    Re(On, In);
    var En = (On.prototype = In.prototype);
    En.constructor = On;
    var xn = En.toString,
      Rn = 'Symbol(test)' == String(In('test')),
      Ln = /^Symbol\((.*)\)[^)]+$/;
    kn(En, 'description', {
      configurable: !0,
      get: function () {
        var e = k(this) ? this.valueOf() : this,
          t = xn.call(e);
        if (E(Tn, e)) return '';
        var n = Rn ? t.slice(7, -1) : t.replace(Ln, '$1');
        return '' === n ? void 0 : n;
      },
    }),
      We({ global: !0, forced: !0 }, { Symbol: On });
  }
  Zt('hasInstance'),
    Zt('isConcatSpreadable'),
    Zt('iterator'),
    Zt('match'),
    Zt('matchAll'),
    Zt('replace'),
    Zt('search'),
    Zt('species'),
    Zt('split'),
    Zt('toPrimitive'),
    Zt('toStringTag'),
    Zt('unscopables'),
    Gt(l.JSON, 'JSON', !0),
    Gt(Math, 'Math', !0),
    We({ global: !0 }, { Reflect: {} }),
    Gt(l.Reflect, 'Reflect', !0),
    le.Symbol;
  var Cn,
    jn,
    Un,
    An = function (e) {
      return function (t, n) {
        var r,
          o,
          i = String(S(t)),
          a = ye(n),
          c = i.length;
        return a < 0 || a >= c
          ? e
            ? ''
            : void 0
          : (r = i.charCodeAt(a)) < 55296 ||
            r > 56319 ||
            a + 1 === c ||
            (o = i.charCodeAt(a + 1)) < 56320 ||
            o > 57343
          ? e
            ? i.charAt(a)
            : r
          : e
          ? i.slice(a, a + 2)
          : o - 56320 + ((r - 55296) << 10) + 65536;
      };
    },
    Pn = { codeAt: An(!1), charAt: An(!0) },
    Fn = !f(function () {
      function e() {}
      return (
        (e.prototype.constructor = null),
        Object.getPrototypeOf(new e()) !== e.prototype
      );
    }),
    Kn = Q('IE_PROTO'),
    Wn = Object.prototype,
    zn = Fn
      ? Object.getPrototypeOf
      : function (e) {
          return (
            (e = T(e)),
            E(e, Kn)
              ? e[Kn]
              : 'function' == typeof e.constructor && e instanceof e.constructor
              ? e.constructor.prototype
              : e instanceof Object
              ? Wn
              : null
          );
        },
    Vn = He('iterator'),
    Zn = !1;
  [].keys &&
    ('next' in (Un = [].keys())
      ? (jn = zn(zn(Un))) !== Object.prototype && (Cn = jn)
      : (Zn = !0)),
    (null == Cn ||
      f(function () {
        var e = {};
        return Cn[Vn].call(e) !== e;
      })) &&
      (Cn = {}),
    E(Cn, Vn) ||
      K(Cn, Vn, function () {
        return this;
      });
  var Xn = { IteratorPrototype: Cn, BUGGY_SAFARI_ITERATORS: Zn },
    Nn = {},
    Gn = Xn.IteratorPrototype,
    Jn = function () {
      return this;
    },
    Dn =
      Object.setPrototypeOf ||
      ('__proto__' in {}
        ? (function () {
            var e,
              t = !1,
              n = {};
            try {
              (e = Object.getOwnPropertyDescriptor(
                Object.prototype,
                '__proto__'
              ).set).call(n, []),
                (t = n instanceof Array);
            } catch (e) {}
            return function (n, r) {
              return (
                A(n),
                (function (e) {
                  if (!k(e) && null !== e)
                    throw TypeError(
                      "Can't set " + String(e) + ' as a prototype'
                    );
                })(r),
                t ? e.call(n, r) : (n.__proto__ = r),
                n
              );
            };
          })()
        : void 0),
    Yn = Xn.IteratorPrototype,
    Bn = Xn.BUGGY_SAFARI_ITERATORS,
    Mn = He('iterator'),
    qn = function () {
      return this;
    },
    Hn = function (e, t, n, r, o, i, a) {
      !(function (e, t, n) {
        var r = t + ' Iterator';
        (e.prototype = At(Gn, { next: v(1, n) })), Gt(e, r, !1), (Nn[r] = Jn);
      })(n, t, r);
      var c,
        s,
        u,
        l = function (e) {
          if (e === o && y) return y;
          if (!Bn && e in p) return p[e];
          switch (e) {
            case 'keys':
            case 'values':
            case 'entries':
              return function () {
                return new n(this, e);
              };
          }
          return function () {
            return new n(this);
          };
        },
        f = t + ' Iterator',
        d = !1,
        p = e.prototype,
        h = p[Mn] || p['@@iterator'] || (o && p[o]),
        y = (!Bn && h) || l(o),
        m = ('Array' == t && p.entries) || h;
      if (
        (m &&
          ((c = zn(m.call(new e()))),
          Yn !== Object.prototype &&
            c.next &&
            (zn(c) !== Yn &&
              (Dn ? Dn(c, Yn) : 'function' != typeof c[Mn] && K(c, Mn, qn)),
            Gt(c, f, !0))),
        'values' == o &&
          h &&
          'values' !== h.name &&
          ((d = !0),
          (y = function () {
            return h.call(this);
          })),
        p[Mn] !== y && K(p, Mn, y),
        (Nn[t] = y),
        o)
      )
        if (
          ((s = {
            values: l('values'),
            keys: i ? y : l('keys'),
            entries: l('entries'),
          }),
          a)
        )
          for (u in s) (Bn || d || !(u in p)) && ue(p, u, s[u]);
        else We({ target: t, proto: !0, forced: Bn || d }, s);
      return s;
    },
    Qn = Pn.charAt,
    $n = se.set,
    er = se.getterFor('String Iterator');
  Hn(
    String,
    'String',
    function (e) {
      $n(this, { type: 'String Iterator', string: String(e), index: 0 });
    },
    function () {
      var e,
        t = er(this),
        n = t.string,
        r = t.index;
      return r >= n.length
        ? { value: void 0, done: !0 }
        : ((e = Qn(n, r)), (t.index += e.length), { value: e, done: !1 });
    }
  );
  var tr = function (e) {
      var t = e.return;
      if (void 0 !== t) return A(t.call(e)).value;
    },
    nr = function (e, t, n, r) {
      try {
        return r ? t(A(n)[0], n[1]) : t(n);
      } catch (t) {
        throw (tr(e), t);
      }
    },
    rr = He('iterator'),
    or = Array.prototype,
    ir = function (e) {
      return void 0 !== e && (Nn.Array === e || or[rr] === e);
    },
    ar = He('iterator'),
    cr = function (e) {
      if (null != e) return e[ar] || e['@@iterator'] || Nn[It(e)];
    },
    sr = He('iterator'),
    ur = !1;
  try {
    var lr = 0,
      fr = {
        next: function () {
          return { done: !!lr++ };
        },
        return: function () {
          ur = !0;
        },
      };
    (fr[sr] = function () {
      return this;
    }),
      Array.from(fr, function () {
        throw 2;
      });
  } catch (e) {}
  var dr = function (e, t) {
      if (!t && !ur) return !1;
      var n = !1;
      try {
        var r = {};
        (r[sr] = function () {
          return {
            next: function () {
              return { done: (n = !0) };
            },
          };
        }),
          e(r);
      } catch (e) {}
      return n;
    },
    pr = !dr(function (e) {
      Array.from(e);
    });
  We(
    { target: 'Array', stat: !0, forced: pr },
    {
      from: function (e) {
        var t,
          n,
          r,
          o,
          i,
          a,
          c = T(e),
          s = 'function' == typeof this ? this : Array,
          u = arguments.length,
          l = u > 1 ? arguments[1] : void 0,
          f = void 0 !== l,
          d = cr(c),
          p = 0;
        if (
          (f && (l = st(l, u > 2 ? arguments[2] : void 0, 2)),
          null == d || (s == Array && ir(d)))
        )
          for (n = new s((t = me(c.length))); t > p; p++)
            (a = f ? l(c[p], p) : c[p]), dt(n, p, a);
        else
          for (
            i = (o = d.call(c)).next, n = new s();
            !(r = i.call(o)).done;
            p++
          )
            (a = f ? nr(o, l, [r.value, p], !0) : r.value), dt(n, p, a);
        return (n.length = p), n;
      },
    }
  ),
    le.Array.from;
  var hr,
    yr = 'undefined' != typeof ArrayBuffer && 'undefined' != typeof DataView,
    vr = F.f,
    mr = l.Int8Array,
    gr = mr && mr.prototype,
    br = l.Uint8ClampedArray,
    wr = br && br.prototype,
    Sr = mr && zn(mr),
    _r = gr && zn(gr),
    kr = Object.prototype,
    Ir = kr.isPrototypeOf,
    Tr = He('toStringTag'),
    Or = q('TYPED_ARRAY_TAG'),
    Er = yr && !!Dn && 'Opera' !== It(l.opera),
    xr = {
      Int8Array: 1,
      Uint8Array: 1,
      Uint8ClampedArray: 1,
      Int16Array: 2,
      Uint16Array: 2,
      Int32Array: 4,
      Uint32Array: 4,
      Float32Array: 4,
      Float64Array: 8,
    },
    Rr = { BigInt64Array: 8, BigUint64Array: 8 },
    Lr = function (e) {
      if (!k(e)) return !1;
      var t = It(e);
      return E(xr, t) || E(Rr, t);
    };
  for (hr in xr) l[hr] || (Er = !1);
  if (
    (!Er || 'function' != typeof Sr || Sr === Function.prototype) &&
    ((Sr = function () {
      throw TypeError('Incorrect invocation');
    }),
    Er)
  )
    for (hr in xr) l[hr] && Dn(l[hr], Sr);
  if ((!Er || !_r || _r === kr) && ((_r = Sr.prototype), Er))
    for (hr in xr) l[hr] && Dn(l[hr].prototype, _r);
  if ((Er && zn(wr) !== _r && Dn(wr, _r), d && !E(_r, Tr)))
    for (hr in (vr(_r, Tr, {
      get: function () {
        return k(this) ? this[Or] : void 0;
      },
    }),
    xr))
      l[hr] && K(l[hr], Or, hr);
  var Cr = function (e) {
      if (Lr(e)) return e;
      throw TypeError('Target is not a typed array');
    },
    jr = function (e) {
      if (Dn) {
        if (Ir.call(Sr, e)) return e;
      } else
        for (var t in xr)
          if (E(xr, hr)) {
            var n = l[t];
            if (n && (e === n || Ir.call(n, e))) return e;
          }
      throw TypeError('Target is not a typed array constructor');
    },
    Ur = function (e, t, n) {
      if (d) {
        if (n)
          for (var r in xr) {
            var o = l[r];
            o && E(o.prototype, e) && delete o.prototype[e];
          }
        (_r[e] && !n) || ue(_r, e, n ? t : (Er && gr[e]) || t);
      }
    },
    Ar = He('species'),
    Pr = Cr,
    Fr = jr,
    Kr = [].slice;
  Ur(
    'slice',
    function (e, t) {
      for (
        var n = Kr.call(Pr(this), e, t),
          r = (function (e, t) {
            var n,
              r = A(e).constructor;
            return void 0 === r || null == (n = A(r)[Ar]) ? t : ct(n);
          })(this, this.constructor),
          o = 0,
          i = n.length,
          a = new (Fr(r))(i);
        i > o;

      )
        a[o] = n[o++];
      return a;
    },
    f(function () {
      new Int8Array(1).slice();
    })
  );
  var Wr = He('unscopables'),
    zr = Array.prototype;
  null == zr[Wr] && F.f(zr, Wr, { configurable: !0, value: At(null) });
  var Vr = function (e) {
      zr[Wr][e] = !0;
    },
    Zr = Se.includes;
  We(
    { target: 'Array', proto: !0 },
    {
      includes: function (e) {
        return Zr(this, e, arguments.length > 1 ? arguments[1] : void 0);
      },
    }
  ),
    Vr('includes'),
    lt('Array', 'includes'),
    We(
      { target: 'String', proto: !0, forced: !tt('includes') },
      {
        includes: function (e) {
          return !!~String(S(this)).indexOf(
            $e(e),
            arguments.length > 1 ? arguments[1] : void 0
          );
        },
      }
    ),
    lt('String', 'includes');
  var Xr = !f(function () {
      return Object.isExtensible(Object.preventExtensions({}));
    }),
    Nr = s(function (e) {
      var t = F.f,
        n = q('meta'),
        r = 0,
        o =
          Object.isExtensible ||
          function () {
            return !0;
          },
        i = function (e) {
          t(e, n, { value: { objectID: 'O' + ++r, weakData: {} } });
        },
        a = (e.exports = {
          REQUIRED: !1,
          fastKey: function (e, t) {
            if (!k(e))
              return 'symbol' == typeof e
                ? e
                : ('string' == typeof e ? 'S' : 'P') + e;
            if (!E(e, n)) {
              if (!o(e)) return 'F';
              if (!t) return 'E';
              i(e);
            }
            return e[n].objectID;
          },
          getWeakData: function (e, t) {
            if (!E(e, n)) {
              if (!o(e)) return !0;
              if (!t) return !1;
              i(e);
            }
            return e[n].weakData;
          },
          onFreeze: function (e) {
            return Xr && a.REQUIRED && o(e) && !E(e, n) && i(e), e;
          },
        });
      $[n] = !0;
    });
  Nr.REQUIRED, Nr.fastKey, Nr.getWeakData, Nr.onFreeze;
  var Gr = function (e, t) {
      (this.stopped = e), (this.result = t);
    },
    Jr = function (e, t, n) {
      var r,
        o,
        i,
        a,
        c,
        s,
        u,
        l = n && n.that,
        f = !(!n || !n.AS_ENTRIES),
        d = !(!n || !n.IS_ITERATOR),
        p = !(!n || !n.INTERRUPTED),
        h = st(t, l, 1 + f + p),
        y = function (e) {
          return r && tr(r), new Gr(!0, e);
        },
        v = function (e) {
          return f
            ? (A(e), p ? h(e[0], e[1], y) : h(e[0], e[1]))
            : p
            ? h(e, y)
            : h(e);
        };
      if (d) r = e;
      else {
        if ('function' != typeof (o = cr(e)))
          throw TypeError('Target is not iterable');
        if (ir(o)) {
          for (i = 0, a = me(e.length); a > i; i++)
            if ((c = v(e[i])) && c instanceof Gr) return c;
          return new Gr(!1);
        }
        r = o.call(e);
      }
      for (s = r.next; !(u = s.call(r)).done; ) {
        try {
          c = v(u.value);
        } catch (e) {
          throw (tr(r), e);
        }
        if ('object' == typeof c && c && c instanceof Gr) return c;
      }
      return new Gr(!1);
    },
    Dr = function (e, t, n) {
      if (!(e instanceof t))
        throw TypeError('Incorrect ' + (n ? n + ' ' : '') + 'invocation');
      return e;
    },
    Yr = function (e, t, n) {
      for (var r in t) ue(e, r, t[r], n);
      return e;
    },
    Br = He('species'),
    Mr = F.f,
    qr = Nr.fastKey,
    Hr = se.set,
    Qr = se.getterFor;
  !(function (e, t, n) {
    var r = -1 !== e.indexOf('Map'),
      o = -1 !== e.indexOf('Weak'),
      i = r ? 'set' : 'add',
      a = l[e],
      c = a && a.prototype,
      s = a,
      u = {},
      d = function (e) {
        var t = c[e];
        ue(
          c,
          e,
          'add' == e
            ? function (e) {
                return t.call(this, 0 === e ? 0 : e), this;
              }
            : 'delete' == e
            ? function (e) {
                return !(o && !k(e)) && t.call(this, 0 === e ? 0 : e);
              }
            : 'get' == e
            ? function (e) {
                return o && !k(e) ? void 0 : t.call(this, 0 === e ? 0 : e);
              }
            : 'has' == e
            ? function (e) {
                return !(o && !k(e)) && t.call(this, 0 === e ? 0 : e);
              }
            : function (e, n) {
                return t.call(this, 0 === e ? 0 : e, n), this;
              }
        );
      };
    if (
      Fe(
        e,
        'function' != typeof a ||
          !(
            o ||
            (c.forEach &&
              !f(function () {
                new a().entries().next();
              }))
          )
      )
    )
      (s = n.getConstructor(t, e, r, i)), (Nr.REQUIRED = !0);
    else if (Fe(e, !0)) {
      var p = new s(),
        h = p[i](o ? {} : -0, 1) != p,
        y = f(function () {
          p.has(1);
        }),
        v = dr(function (e) {
          new a(e);
        }),
        m =
          !o &&
          f(function () {
            for (var e = new a(), t = 5; t--; ) e[i](t, t);
            return !e.has(-0);
          });
      v ||
        (((s = t(function (t, n) {
          Dr(t, s, e);
          var o = (function (e, t, n) {
            var r, o;
            return (
              Dn &&
                'function' == typeof (r = t.constructor) &&
                r !== n &&
                k((o = r.prototype)) &&
                o !== n.prototype &&
                Dn(e, o),
              e
            );
          })(new a(), t, s);
          return null != n && Jr(n, o[i], { that: o, AS_ENTRIES: r }), o;
        })).prototype = c),
        (c.constructor = s)),
        (y || m) && (d('delete'), d('has'), r && d('get')),
        (m || h) && d(i),
        o && c.clear && delete c.clear;
    }
    (u[e] = s),
      We({ global: !0, forced: s != a }, u),
      Gt(s, e),
      o || n.setStrong(s, e, r);
  })(
    'Set',
    function (e) {
      return function () {
        return e(this, arguments.length ? arguments[0] : void 0);
      };
    },
    {
      getConstructor: function (e, t, n, r) {
        var o = e(function (e, i) {
            Dr(e, o, t),
              Hr(e, {
                type: t,
                index: At(null),
                first: void 0,
                last: void 0,
                size: 0,
              }),
              d || (e.size = 0),
              null != i && Jr(i, e[r], { that: e, AS_ENTRIES: n });
          }),
          i = Qr(t),
          a = function (e, t, n) {
            var r,
              o,
              a = i(e),
              s = c(e, t);
            return (
              s
                ? (s.value = n)
                : ((a.last = s = {
                    index: (o = qr(t, !0)),
                    key: t,
                    value: n,
                    previous: (r = a.last),
                    next: void 0,
                    removed: !1,
                  }),
                  a.first || (a.first = s),
                  r && (r.next = s),
                  d ? a.size++ : e.size++,
                  'F' !== o && (a.index[o] = s)),
              e
            );
          },
          c = function (e, t) {
            var n,
              r = i(e),
              o = qr(t);
            if ('F' !== o) return r.index[o];
            for (n = r.first; n; n = n.next) if (n.key == t) return n;
          };
        return (
          Yr(o.prototype, {
            clear: function () {
              for (var e = i(this), t = e.index, n = e.first; n; )
                (n.removed = !0),
                  n.previous && (n.previous = n.previous.next = void 0),
                  delete t[n.index],
                  (n = n.next);
              (e.first = e.last = void 0), d ? (e.size = 0) : (this.size = 0);
            },
            delete: function (e) {
              var t = this,
                n = i(t),
                r = c(t, e);
              if (r) {
                var o = r.next,
                  a = r.previous;
                delete n.index[r.index],
                  (r.removed = !0),
                  a && (a.next = o),
                  o && (o.previous = a),
                  n.first == r && (n.first = o),
                  n.last == r && (n.last = a),
                  d ? n.size-- : t.size--;
              }
              return !!r;
            },
            forEach: function (e) {
              for (
                var t,
                  n = i(this),
                  r = st(e, arguments.length > 1 ? arguments[1] : void 0, 3);
                (t = t ? t.next : n.first);

              )
                for (r(t.value, t.key, this); t && t.removed; ) t = t.previous;
            },
            has: function (e) {
              return !!c(this, e);
            },
          }),
          Yr(
            o.prototype,
            n
              ? {
                  get: function (e) {
                    var t = c(this, e);
                    return t && t.value;
                  },
                  set: function (e, t) {
                    return a(this, 0 === e ? 0 : e, t);
                  },
                }
              : {
                  add: function (e) {
                    return a(this, (e = 0 === e ? 0 : e), e);
                  },
                }
          ),
          d &&
            Mr(o.prototype, 'size', {
              get: function () {
                return i(this).size;
              },
            }),
          o
        );
      },
      setStrong: function (e, t, n) {
        var r = t + ' Iterator',
          o = Qr(t),
          i = Qr(r);
        Hn(
          e,
          t,
          function (e, t) {
            Hr(this, {
              type: r,
              target: e,
              state: o(e),
              kind: t,
              last: void 0,
            });
          },
          function () {
            for (var e = i(this), t = e.kind, n = e.last; n && n.removed; )
              n = n.previous;
            return e.target && (e.last = n = n ? n.next : e.state.first)
              ? 'keys' == t
                ? { value: n.key, done: !1 }
                : 'values' == t
                ? { value: n.value, done: !1 }
                : { value: [n.key, n.value], done: !1 }
              : ((e.target = void 0), { value: void 0, done: !0 });
          },
          n ? 'entries' : 'values',
          !n,
          !0
        ),
          (function (e) {
            var t = de(e),
              n = F.f;
            d &&
              t &&
              !t[Br] &&
              n(t, Br, {
                configurable: !0,
                get: function () {
                  return this;
                },
              });
          })(t);
      },
    }
  );
  var $r = {
      CSSRuleList: 0,
      CSSStyleDeclaration: 0,
      CSSValueList: 0,
      ClientRectList: 0,
      DOMRectList: 0,
      DOMStringList: 0,
      DOMTokenList: 1,
      DataTransferItemList: 0,
      FileList: 0,
      HTMLAllCollection: 0,
      HTMLCollection: 0,
      HTMLFormElement: 0,
      HTMLSelectElement: 0,
      MediaList: 0,
      MimeTypeArray: 0,
      NamedNodeMap: 0,
      NodeList: 1,
      PaintRequestList: 0,
      Plugin: 0,
      PluginArray: 0,
      SVGLengthList: 0,
      SVGNumberList: 0,
      SVGPathSegList: 0,
      SVGPointList: 0,
      SVGStringList: 0,
      SVGTransformList: 0,
      SourceBufferList: 0,
      StyleSheetList: 0,
      TextTrackCueList: 0,
      TextTrackList: 0,
      TouchList: 0,
    },
    eo = se.set,
    to = se.getterFor('Array Iterator'),
    no = Hn(
      Array,
      'Array',
      function (e, t) {
        eo(this, { type: 'Array Iterator', target: _(e), index: 0, kind: t });
      },
      function () {
        var e = to(this),
          t = e.target,
          n = e.kind,
          r = e.index++;
        return !t || r >= t.length
          ? ((e.target = void 0), { value: void 0, done: !0 })
          : 'keys' == n
          ? { value: r, done: !1 }
          : 'values' == n
          ? { value: t[r], done: !1 }
          : { value: [r, t[r]], done: !1 };
      },
      'values'
    );
  (Nn.Arguments = Nn.Array), Vr('keys'), Vr('values'), Vr('entries');
  var ro = He('iterator'),
    oo = He('toStringTag'),
    io = no.values;
  for (var ao in $r) {
    var co = l[ao],
      so = co && co.prototype;
    if (so) {
      if (so[ro] !== io)
        try {
          K(so, ro, io);
        } catch (e) {
          so[ro] = io;
        }
      if ((so[oo] || K(so, oo, ao), $r[ao]))
        for (var uo in no)
          if (so[uo] !== no[uo])
            try {
              K(so, uo, no[uo]);
            } catch (e) {
              so[uo] = no[uo];
            }
    }
  }
  function lo(e) {
    var t = this.constructor;
    return this.then(
      function (n) {
        return t.resolve(e()).then(function () {
          return n;
        });
      },
      function (n) {
        return t.resolve(e()).then(function () {
          return t.reject(n);
        });
      }
    );
  }
  function fo(e) {
    return new this(function (t, n) {
      if (!e || void 0 === e.length)
        return n(
          new TypeError(
            typeof e +
              ' ' +
              e +
              ' is not iterable(cannot read property Symbol(Symbol.iterator))'
          )
        );
      var r = Array.prototype.slice.call(e);
      if (0 === r.length) return t([]);
      var o = r.length;
      function i(e, n) {
        if (n && ('object' == typeof n || 'function' == typeof n)) {
          var a = n.then;
          if ('function' == typeof a)
            return void a.call(
              n,
              function (t) {
                i(e, t);
              },
              function (n) {
                (r[e] = { status: 'rejected', reason: n }), 0 == --o && t(r);
              }
            );
        }
        (r[e] = { status: 'fulfilled', value: n }), 0 == --o && t(r);
      }
      for (var a = 0; a < r.length; a++) i(a, r[a]);
    });
  }
  le.Set;
  var po = setTimeout;
  function ho(e) {
    return Boolean(e && void 0 !== e.length);
  }
  function yo() {}
  function vo(e) {
    if (!(this instanceof vo))
      throw new TypeError('Promises must be constructed via new');
    if ('function' != typeof e) throw new TypeError('not a function');
    (this._state = 0),
      (this._handled = !1),
      (this._value = void 0),
      (this._deferreds = []),
      _o(e, this);
  }
  function mo(e, t) {
    for (; 3 === e._state; ) e = e._value;
    0 !== e._state
      ? ((e._handled = !0),
        vo._immediateFn(function () {
          var n = 1 === e._state ? t.onFulfilled : t.onRejected;
          if (null !== n) {
            var r;
            try {
              r = n(e._value);
            } catch (e) {
              return void bo(t.promise, e);
            }
            go(t.promise, r);
          } else (1 === e._state ? go : bo)(t.promise, e._value);
        }))
      : e._deferreds.push(t);
  }
  function go(e, t) {
    try {
      if (t === e)
        throw new TypeError('A promise cannot be resolved with itself.');
      if (t && ('object' == typeof t || 'function' == typeof t)) {
        var n = t.then;
        if (t instanceof vo) return (e._state = 3), (e._value = t), void wo(e);
        if ('function' == typeof n)
          return void _o(
            ((r = n),
            (o = t),
            function () {
              r.apply(o, arguments);
            }),
            e
          );
      }
      (e._state = 1), (e._value = t), wo(e);
    } catch (t) {
      bo(e, t);
    }
    var r, o;
  }
  function bo(e, t) {
    (e._state = 2), (e._value = t), wo(e);
  }
  function wo(e) {
    2 === e._state &&
      0 === e._deferreds.length &&
      vo._immediateFn(function () {
        e._handled || vo._unhandledRejectionFn(e._value);
      });
    for (var t = 0, n = e._deferreds.length; t < n; t++) mo(e, e._deferreds[t]);
    e._deferreds = null;
  }
  function So(e, t, n) {
    (this.onFulfilled = 'function' == typeof e ? e : null),
      (this.onRejected = 'function' == typeof t ? t : null),
      (this.promise = n);
  }
  function _o(e, t) {
    var n = !1;
    try {
      e(
        function (e) {
          n || ((n = !0), go(t, e));
        },
        function (e) {
          n || ((n = !0), bo(t, e));
        }
      );
    } catch (e) {
      if (n) return;
      (n = !0), bo(t, e);
    }
  }
  (vo.prototype.catch = function (e) {
    return this.then(null, e);
  }),
    (vo.prototype.then = function (e, t) {
      var n = new this.constructor(yo);
      return mo(this, new So(e, t, n)), n;
    }),
    (vo.prototype.finally = lo),
    (vo.all = function (e) {
      return new vo(function (t, n) {
        if (!ho(e)) return n(new TypeError('Promise.all accepts an array'));
        var r = Array.prototype.slice.call(e);
        if (0 === r.length) return t([]);
        var o = r.length;
        function i(e, a) {
          try {
            if (a && ('object' == typeof a || 'function' == typeof a)) {
              var c = a.then;
              if ('function' == typeof c)
                return void c.call(
                  a,
                  function (t) {
                    i(e, t);
                  },
                  n
                );
            }
            (r[e] = a), 0 == --o && t(r);
          } catch (e) {
            n(e);
          }
        }
        for (var a = 0; a < r.length; a++) i(a, r[a]);
      });
    }),
    (vo.allSettled = fo),
    (vo.resolve = function (e) {
      return e && 'object' == typeof e && e.constructor === vo
        ? e
        : new vo(function (t) {
            t(e);
          });
    }),
    (vo.reject = function (e) {
      return new vo(function (t, n) {
        n(e);
      });
    }),
    (vo.race = function (e) {
      return new vo(function (t, n) {
        if (!ho(e)) return n(new TypeError('Promise.race accepts an array'));
        for (var r = 0, o = e.length; r < o; r++) vo.resolve(e[r]).then(t, n);
      });
    }),
    (vo._immediateFn =
      ('function' == typeof setImmediate &&
        function (e) {
          setImmediate(e);
        }) ||
      function (e) {
        po(e, 0);
      }),
    (vo._unhandledRejectionFn = function (e) {
      'undefined' != typeof console &&
        console &&
        console.warn('Possible Unhandled Promise Rejection:', e);
    });
  var ko = (function () {
    if ('undefined' != typeof self) return self;
    if ('undefined' != typeof window) return window;
    if ('undefined' != typeof global) return global;
    throw new Error('unable to locate global object');
  })();
  'function' != typeof ko.Promise
    ? (ko.Promise = vo)
    : ko.Promise.prototype.finally
    ? ko.Promise.allSettled || (ko.Promise.allSettled = fo)
    : (ko.Promise.prototype.finally = lo),
    (function (e) {
      function t() {}
      function n(e, t) {
        if (
          ((e = void 0 === e ? 'utf-8' : e),
          (t = void 0 === t ? { fatal: !1 } : t),
          -1 === o.indexOf(e.toLowerCase()))
        )
          throw new RangeError(
            "Failed to construct 'TextDecoder': The encoding label provided ('" +
              e +
              "') is invalid."
          );
        if (t.fatal)
          throw Error(
            "Failed to construct 'TextDecoder': the 'fatal' option is unsupported."
          );
      }
      function r(e) {
        for (
          var t = 0,
            n = Math.min(65536, e.length + 1),
            r = new Uint16Array(n),
            o = [],
            i = 0;
          ;

        ) {
          var a = t < e.length;
          if (!a || i >= n - 1) {
            if ((o.push(String.fromCharCode.apply(null, r.subarray(0, i))), !a))
              return o.join('');
            (e = e.subarray(t)), (i = t = 0);
          }
          if (0 == (128 & (a = e[t++]))) r[i++] = a;
          else if (192 == (224 & a)) {
            var c = 63 & e[t++];
            r[i++] = ((31 & a) << 6) | c;
          } else if (224 == (240 & a)) {
            c = 63 & e[t++];
            var s = 63 & e[t++];
            r[i++] = ((31 & a) << 12) | (c << 6) | s;
          } else if (240 == (248 & a)) {
            65535 <
              (a =
                ((7 & a) << 18) |
                ((c = 63 & e[t++]) << 12) |
                ((s = 63 & e[t++]) << 6) |
                (63 & e[t++])) &&
              ((a -= 65536),
              (r[i++] = ((a >>> 10) & 1023) | 55296),
              (a = 56320 | (1023 & a))),
              (r[i++] = a);
          }
        }
      }
      if (e.TextEncoder && e.TextDecoder) return !1;
      var o = ['utf-8', 'utf8', 'unicode-1-1-utf-8'];
      Object.defineProperty(t.prototype, 'encoding', { value: 'utf-8' }),
        (t.prototype.encode = function (e, t) {
          if ((t = void 0 === t ? { stream: !1 } : t).stream)
            throw Error(
              "Failed to encode: the 'stream' option is unsupported."
            );
          t = 0;
          for (
            var n = e.length,
              r = 0,
              o = Math.max(32, n + (n >>> 1) + 7),
              i = new Uint8Array((o >>> 3) << 3);
            t < n;

          ) {
            var a = e.charCodeAt(t++);
            if (55296 <= a && 56319 >= a) {
              if (t < n) {
                var c = e.charCodeAt(t);
                56320 == (64512 & c) &&
                  (++t, (a = ((1023 & a) << 10) + (1023 & c) + 65536));
              }
              if (55296 <= a && 56319 >= a) continue;
            }
            if (
              (r + 4 > i.length &&
                ((o += 8),
                (o = ((o *= 1 + (t / e.length) * 2) >>> 3) << 3),
                (c = new Uint8Array(o)).set(i),
                (i = c)),
              0 == (4294967168 & a))
            )
              i[r++] = a;
            else {
              if (0 == (4294965248 & a)) i[r++] = ((a >>> 6) & 31) | 192;
              else if (0 == (4294901760 & a))
                (i[r++] = ((a >>> 12) & 15) | 224),
                  (i[r++] = ((a >>> 6) & 63) | 128);
              else {
                if (0 != (4292870144 & a)) continue;
                (i[r++] = ((a >>> 18) & 7) | 240),
                  (i[r++] = ((a >>> 12) & 63) | 128),
                  (i[r++] = ((a >>> 6) & 63) | 128);
              }
              i[r++] = (63 & a) | 128;
            }
          }
          return i.slice ? i.slice(0, r) : i.subarray(0, r);
        }),
        Object.defineProperty(n.prototype, 'encoding', { value: 'utf-8' }),
        Object.defineProperty(n.prototype, 'fatal', { value: !1 }),
        Object.defineProperty(n.prototype, 'ignoreBOM', { value: !1 });
      var i = r;
      'function' == typeof Buffer && Buffer.from
        ? (i = function (e) {
            return Buffer.from(e.buffer, e.byteOffset, e.byteLength).toString(
              'utf-8'
            );
          })
        : 'function' == typeof Blob &&
          'function' == typeof URL &&
          'function' == typeof URL.createObjectURL &&
          (i = function (e) {
            var t = URL.createObjectURL(
              new Blob([e], { type: 'text/plain;charset=UTF-8' })
            );
            try {
              var n = new XMLHttpRequest();
              return n.open('GET', t, !1), n.send(), n.responseText;
            } catch (t) {
              return r(e);
            } finally {
              URL.revokeObjectURL(t);
            }
          }),
        (n.prototype.decode = function (e, t) {
          if ((t = void 0 === t ? { stream: !1 } : t).stream)
            throw Error(
              "Failed to decode: the 'stream' option is unsupported."
            );
          return (
            (e =
              e instanceof Uint8Array
                ? e
                : e.buffer instanceof ArrayBuffer
                ? new Uint8Array(e.buffer)
                : new Uint8Array(e)),
            i(e)
          );
        }),
        (e.TextEncoder = t),
        (e.TextDecoder = n);
    })('undefined' != typeof window ? window : a),
    (function () {
      function e(e, t) {
        if (!(e instanceof t))
          throw new TypeError('Cannot call a class as a function');
      }
      function t(e, t) {
        for (var n = 0; n < t.length; n++) {
          var r = t[n];
          (r.enumerable = r.enumerable || !1),
            (r.configurable = !0),
            'value' in r && (r.writable = !0),
            Object.defineProperty(e, r.key, r);
        }
      }
      function n(e, n, r) {
        return n && t(e.prototype, n), r && t(e, r), e;
      }
      function r(e, t) {
        if ('function' != typeof t && null !== t)
          throw new TypeError(
            'Super expression must either be null or a function'
          );
        (e.prototype = Object.create(t && t.prototype, {
          constructor: { value: e, writable: !0, configurable: !0 },
        })),
          t && i(e, t);
      }
      function o(e) {
        return (o = Object.setPrototypeOf
          ? Object.getPrototypeOf
          : function (e) {
              return e.__proto__ || Object.getPrototypeOf(e);
            })(e);
      }
      function i(e, t) {
        return (i =
          Object.setPrototypeOf ||
          function (e, t) {
            return (e.__proto__ = t), e;
          })(e, t);
      }
      function c() {
        if ('undefined' == typeof Reflect || !Reflect.construct) return !1;
        if (Reflect.construct.sham) return !1;
        if ('function' == typeof Proxy) return !0;
        try {
          return (
            Date.prototype.toString.call(
              Reflect.construct(Date, [], function () {})
            ),
            !0
          );
        } catch (e) {
          return !1;
        }
      }
      function s(e) {
        if (void 0 === e)
          throw new ReferenceError(
            "this hasn't been initialised - super() hasn't been called"
          );
        return e;
      }
      function u(e, t) {
        return !t || ('object' != typeof t && 'function' != typeof t)
          ? s(e)
          : t;
      }
      function l(e) {
        var t = c();
        return function () {
          var n,
            r = o(e);
          if (t) {
            var i = o(this).constructor;
            n = Reflect.construct(r, arguments, i);
          } else n = r.apply(this, arguments);
          return u(this, n);
        };
      }
      function f(e, t) {
        for (
          ;
          !Object.prototype.hasOwnProperty.call(e, t) && null !== (e = o(e));

        );
        return e;
      }
      function d(e, t, n) {
        return (d =
          'undefined' != typeof Reflect && Reflect.get
            ? Reflect.get
            : function (e, t, n) {
                var r = f(e, t);
                if (r) {
                  var o = Object.getOwnPropertyDescriptor(r, t);
                  return o.get ? o.get.call(n) : o.value;
                }
              })(e, t, n || e);
      }
      var p = (function () {
          function t() {
            e(this, t),
              Object.defineProperty(this, 'listeners', {
                value: {},
                writable: !0,
                configurable: !0,
              });
          }
          return (
            n(t, [
              {
                key: 'addEventListener',
                value: function (e, t, n) {
                  e in this.listeners || (this.listeners[e] = []),
                    this.listeners[e].push({ callback: t, options: n });
                },
              },
              {
                key: 'removeEventListener',
                value: function (e, t) {
                  if (e in this.listeners)
                    for (
                      var n = this.listeners[e], r = 0, o = n.length;
                      r < o;
                      r++
                    )
                      if (n[r].callback === t) return void n.splice(r, 1);
                },
              },
              {
                key: 'dispatchEvent',
                value: function (e) {
                  if (e.type in this.listeners) {
                    for (
                      var t = this.listeners[e.type].slice(),
                        n = 0,
                        r = t.length;
                      n < r;
                      n++
                    ) {
                      var o = t[n];
                      try {
                        o.callback.call(this, e);
                      } catch (e) {
                        Promise.resolve().then(function () {
                          throw e;
                        });
                      }
                      o.options &&
                        o.options.once &&
                        this.removeEventListener(e.type, o.callback);
                    }
                    return !e.defaultPrevented;
                  }
                },
              },
            ]),
            t
          );
        })(),
        h = (function (t) {
          r(a, t);
          var i = l(a);
          function a() {
            var t;
            return (
              e(this, a),
              (t = i.call(this)).listeners || p.call(s(t)),
              Object.defineProperty(s(t), 'aborted', {
                value: !1,
                writable: !0,
                configurable: !0,
              }),
              Object.defineProperty(s(t), 'onabort', {
                value: null,
                writable: !0,
                configurable: !0,
              }),
              t
            );
          }
          return (
            n(a, [
              {
                key: 'toString',
                value: function () {
                  return '[object AbortSignal]';
                },
              },
              {
                key: 'dispatchEvent',
                value: function (e) {
                  'abort' === e.type &&
                    ((this.aborted = !0),
                    'function' == typeof this.onabort &&
                      this.onabort.call(this, e)),
                    d(o(a.prototype), 'dispatchEvent', this).call(this, e);
                },
              },
            ]),
            a
          );
        })(p),
        y = (function () {
          function t() {
            e(this, t),
              Object.defineProperty(this, 'signal', {
                value: new h(),
                writable: !0,
                configurable: !0,
              });
          }
          return (
            n(t, [
              {
                key: 'abort',
                value: function () {
                  var e;
                  try {
                    e = new Event('abort');
                  } catch (t) {
                    'undefined' != typeof document
                      ? document.createEvent
                        ? (e = document.createEvent('Event')).initEvent(
                            'abort',
                            !1,
                            !1
                          )
                        : ((e = document.createEventObject()).type = 'abort')
                      : (e = { type: 'abort', bubbles: !1, cancelable: !1 });
                  }
                  this.signal.dispatchEvent(e);
                },
              },
              {
                key: 'toString',
                value: function () {
                  return '[object AbortController]';
                },
              },
            ]),
            t
          );
        })();
      function v(e) {
        return e.__FORCE_INSTALL_ABORTCONTROLLER_POLYFILL
          ? (console.log(
              '__FORCE_INSTALL_ABORTCONTROLLER_POLYFILL=true is set, will force install polyfill'
            ),
            !0)
          : ('function' == typeof e.Request &&
              !e.Request.prototype.hasOwnProperty('signal')) ||
              !e.AbortController;
      }
      'undefined' != typeof Symbol &&
        Symbol.toStringTag &&
        ((y.prototype[Symbol.toStringTag] = 'AbortController'),
        (h.prototype[Symbol.toStringTag] = 'AbortSignal')),
        (function (e) {
          v(e) && ((e.AbortController = y), (e.AbortSignal = h));
        })('undefined' != typeof self ? self : a);
    })();
  var Io = s(function (e, t) {
    Object.defineProperty(t, '__esModule', { value: !0 });
    var n = (function () {
      function e() {
        var e = this;
        (this.locked = new Map()),
          (this.addToLocked = function (t, n) {
            var r = e.locked.get(t);
            void 0 === r
              ? void 0 === n
                ? e.locked.set(t, [])
                : e.locked.set(t, [n])
              : void 0 !== n && (r.unshift(n), e.locked.set(t, r));
          }),
          (this.isLocked = function (t) {
            return e.locked.has(t);
          }),
          (this.lock = function (t) {
            return new Promise(function (n, r) {
              e.isLocked(t) ? e.addToLocked(t, n) : (e.addToLocked(t), n());
            });
          }),
          (this.unlock = function (t) {
            var n = e.locked.get(t);
            if (void 0 !== n && 0 !== n.length) {
              var r = n.pop();
              e.locked.set(t, n), void 0 !== r && setTimeout(r, 0);
            } else e.locked.delete(t);
          });
      }
      return (
        (e.getInstance = function () {
          return void 0 === e.instance && (e.instance = new e()), e.instance;
        }),
        e
      );
    })();
    t.default = function () {
      return n.getInstance();
    };
  });
  c(Io);
  var To = c(
      s(function (e, t) {
        var n =
            (a && a.__awaiter) ||
            function (e, t, n, r) {
              return new (n || (n = Promise))(function (o, i) {
                function a(e) {
                  try {
                    s(r.next(e));
                  } catch (e) {
                    i(e);
                  }
                }
                function c(e) {
                  try {
                    s(r.throw(e));
                  } catch (e) {
                    i(e);
                  }
                }
                function s(e) {
                  e.done
                    ? o(e.value)
                    : new n(function (t) {
                        t(e.value);
                      }).then(a, c);
                }
                s((r = r.apply(e, t || [])).next());
              });
            },
          r =
            (a && a.__generator) ||
            function (e, t) {
              var n,
                r,
                o,
                i,
                a = {
                  label: 0,
                  sent: function () {
                    if (1 & o[0]) throw o[1];
                    return o[1];
                  },
                  trys: [],
                  ops: [],
                };
              return (
                (i = { next: c(0), throw: c(1), return: c(2) }),
                'function' == typeof Symbol &&
                  (i[Symbol.iterator] = function () {
                    return this;
                  }),
                i
              );
              function c(i) {
                return function (c) {
                  return (function (i) {
                    if (n)
                      throw new TypeError('Generator is already executing.');
                    for (; a; )
                      try {
                        if (
                          ((n = 1),
                          r &&
                            (o =
                              2 & i[0]
                                ? r.return
                                : i[0]
                                ? r.throw || ((o = r.return) && o.call(r), 0)
                                : r.next) &&
                            !(o = o.call(r, i[1])).done)
                        )
                          return o;
                        switch (
                          ((r = 0), o && (i = [2 & i[0], o.value]), i[0])
                        ) {
                          case 0:
                          case 1:
                            o = i;
                            break;
                          case 4:
                            return a.label++, { value: i[1], done: !1 };
                          case 5:
                            a.label++, (r = i[1]), (i = [0]);
                            continue;
                          case 7:
                            (i = a.ops.pop()), a.trys.pop();
                            continue;
                          default:
                            if (
                              !((o = a.trys),
                              (o = o.length > 0 && o[o.length - 1]) ||
                                (6 !== i[0] && 2 !== i[0]))
                            ) {
                              a = 0;
                              continue;
                            }
                            if (
                              3 === i[0] &&
                              (!o || (i[1] > o[0] && i[1] < o[3]))
                            ) {
                              a.label = i[1];
                              break;
                            }
                            if (6 === i[0] && a.label < o[1]) {
                              (a.label = o[1]), (o = i);
                              break;
                            }
                            if (o && a.label < o[2]) {
                              (a.label = o[2]), a.ops.push(i);
                              break;
                            }
                            o[2] && a.ops.pop(), a.trys.pop();
                            continue;
                        }
                        i = t.call(e, a);
                      } catch (e) {
                        (i = [6, e]), (r = 0);
                      } finally {
                        n = o = 0;
                      }
                    if (5 & i[0]) throw i[1];
                    return { value: i[0] ? i[1] : void 0, done: !0 };
                  })([i, c]);
                };
              }
            };
        Object.defineProperty(t, '__esModule', { value: !0 });
        var o = 'browser-tabs-lock-key';
        function i(e) {
          return new Promise(function (t) {
            return setTimeout(t, e);
          });
        }
        function c(e) {
          for (
            var t =
                '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz',
              n = '',
              r = 0;
            r < e;
            r++
          ) {
            n += t[Math.floor(Math.random() * t.length)];
          }
          return n;
        }
        var s = (function () {
          function e() {
            (this.acquiredIatSet = new Set()),
              (this.id = Date.now().toString() + c(15)),
              (this.acquireLock = this.acquireLock.bind(this)),
              (this.releaseLock = this.releaseLock.bind(this)),
              (this.releaseLock__private__ = this.releaseLock__private__.bind(
                this
              )),
              (this.waitForSomethingToChange = this.waitForSomethingToChange.bind(
                this
              )),
              (this.refreshLockWhileAcquired = this.refreshLockWhileAcquired.bind(
                this
              )),
              void 0 === e.waiters && (e.waiters = []);
          }
          return (
            (e.prototype.acquireLock = function (t, a) {
              return (
                void 0 === a && (a = 5e3),
                n(this, void 0, void 0, function () {
                  var n, s, u, l, f, d;
                  return r(this, function (r) {
                    switch (r.label) {
                      case 0:
                        (n = Date.now() + c(4)),
                          (s = Date.now() + a),
                          (u = o + '-' + t),
                          (l = window.localStorage),
                          (r.label = 1);
                      case 1:
                        return Date.now() < s ? [4, i(30)] : [3, 8];
                      case 2:
                        return (
                          r.sent(),
                          null !== l.getItem(u)
                            ? [3, 5]
                            : ((f = this.id + '-' + t + '-' + n),
                              [4, i(Math.floor(25 * Math.random()))])
                        );
                      case 3:
                        return (
                          r.sent(),
                          l.setItem(
                            u,
                            JSON.stringify({
                              id: this.id,
                              iat: n,
                              timeoutKey: f,
                              timeAcquired: Date.now(),
                              timeRefreshed: Date.now(),
                            })
                          ),
                          [4, i(30)]
                        );
                      case 4:
                        return (
                          r.sent(),
                          null !== (d = l.getItem(u)) &&
                          (d = JSON.parse(d)).id === this.id &&
                          d.iat === n
                            ? (this.acquiredIatSet.add(n),
                              this.refreshLockWhileAcquired(u, n),
                              [2, !0])
                            : [3, 7]
                        );
                      case 5:
                        return (
                          e.lockCorrector(),
                          [4, this.waitForSomethingToChange(s)]
                        );
                      case 6:
                        r.sent(), (r.label = 7);
                      case 7:
                        return (n = Date.now() + c(4)), [3, 1];
                      case 8:
                        return [2, !1];
                    }
                  });
                })
              );
            }),
            (e.prototype.refreshLockWhileAcquired = function (e, t) {
              return n(this, void 0, void 0, function () {
                var o = this;
                return r(this, function (i) {
                  return (
                    setTimeout(function () {
                      return n(o, void 0, void 0, function () {
                        var n, o;
                        return r(this, function (r) {
                          switch (r.label) {
                            case 0:
                              return [4, Io.default().lock(t)];
                            case 1:
                              return (
                                r.sent(),
                                this.acquiredIatSet.has(t)
                                  ? ((n = window.localStorage),
                                    null === (o = n.getItem(e))
                                      ? (Io.default().unlock(t), [2])
                                      : (((o = JSON.parse(
                                          o
                                        )).timeRefreshed = Date.now()),
                                        n.setItem(e, JSON.stringify(o)),
                                        Io.default().unlock(t),
                                        this.refreshLockWhileAcquired(e, t),
                                        [2]))
                                  : (Io.default().unlock(t), [2])
                              );
                          }
                        });
                      });
                    }, 1e3),
                    [2]
                  );
                });
              });
            }),
            (e.prototype.waitForSomethingToChange = function (t) {
              return n(this, void 0, void 0, function () {
                return r(this, function (n) {
                  switch (n.label) {
                    case 0:
                      return [
                        4,
                        new Promise(function (n) {
                          var r = !1,
                            o = Date.now(),
                            i = !1;
                          function a() {
                            if (
                              (i ||
                                (window.removeEventListener('storage', a),
                                e.removeFromWaiting(a),
                                clearTimeout(c),
                                (i = !0)),
                              !r)
                            ) {
                              r = !0;
                              var t = 50 - (Date.now() - o);
                              t > 0 ? setTimeout(n, t) : n();
                            }
                          }
                          window.addEventListener('storage', a),
                            e.addToWaiting(a);
                          var c = setTimeout(a, Math.max(0, t - Date.now()));
                        }),
                      ];
                    case 1:
                      return n.sent(), [2];
                  }
                });
              });
            }),
            (e.addToWaiting = function (t) {
              this.removeFromWaiting(t),
                void 0 !== e.waiters && e.waiters.push(t);
            }),
            (e.removeFromWaiting = function (t) {
              void 0 !== e.waiters &&
                (e.waiters = e.waiters.filter(function (e) {
                  return e !== t;
                }));
            }),
            (e.notifyWaiters = function () {
              void 0 !== e.waiters &&
                e.waiters.slice().forEach(function (e) {
                  return e();
                });
            }),
            (e.prototype.releaseLock = function (e) {
              return n(this, void 0, void 0, function () {
                return r(this, function (t) {
                  switch (t.label) {
                    case 0:
                      return [4, this.releaseLock__private__(e)];
                    case 1:
                      return [2, t.sent()];
                  }
                });
              });
            }),
            (e.prototype.releaseLock__private__ = function (t) {
              return n(this, void 0, void 0, function () {
                var n, i, a;
                return r(this, function (r) {
                  switch (r.label) {
                    case 0:
                      return (
                        (n = window.localStorage),
                        (i = o + '-' + t),
                        null === (a = n.getItem(i))
                          ? [2]
                          : (a = JSON.parse(a)).id !== this.id
                          ? [3, 2]
                          : [4, Io.default().lock(a.iat)]
                      );
                    case 1:
                      r.sent(),
                        this.acquiredIatSet.delete(a.iat),
                        n.removeItem(i),
                        Io.default().unlock(a.iat),
                        e.notifyWaiters(),
                        (r.label = 2);
                    case 2:
                      return [2];
                  }
                });
              });
            }),
            (e.lockCorrector = function () {
              for (
                var t = Date.now() - 5e3,
                  n = window.localStorage,
                  r = Object.keys(n),
                  i = !1,
                  a = 0;
                a < r.length;
                a++
              ) {
                var c = r[a];
                if (c.includes(o)) {
                  var s = n.getItem(c);
                  null !== s &&
                    ((void 0 === (s = JSON.parse(s)).timeRefreshed &&
                      s.timeAcquired < t) ||
                      (void 0 !== s.timeRefreshed && s.timeRefreshed < t)) &&
                    (n.removeItem(c), (i = !0));
                }
              }
              i && e.notifyWaiters();
            }),
            (e.waiters = void 0),
            e
          );
        })();
        t.default = s;
      })
    ),
    Oo = { timeoutInSeconds: 60 },
    Eo = [
      'login_required',
      'consent_required',
      'interaction_required',
      'account_selection_required',
      'access_denied',
    ],
    xo = { name: 'auth0-spa-js', version: '1.15.0' },
    Ro = (function (e) {
      function n(t, r) {
        var o = e.call(this, r) || this;
        return (
          (o.error = t),
          (o.error_description = r),
          Object.setPrototypeOf(o, n.prototype),
          o
        );
      }
      return (
        t(n, e),
        (n.fromPayload = function (e) {
          return new n(e.error, e.error_description);
        }),
        n
      );
    })(Error),
    Lo = (function (e) {
      function n(t, r, o, i) {
        void 0 === i && (i = null);
        var a = e.call(this, t, r) || this;
        return (
          (a.state = o),
          (a.appState = i),
          Object.setPrototypeOf(a, n.prototype),
          a
        );
      }
      return t(n, e), n;
    })(Ro),
    Co = (function (e) {
      function n() {
        var t = e.call(this, 'timeout', 'Timeout') || this;
        return Object.setPrototypeOf(t, n.prototype), t;
      }
      return t(n, e), n;
    })(Ro),
    jo = (function (e) {
      function n(t) {
        var r = e.call(this) || this;
        return (r.popup = t), Object.setPrototypeOf(r, n.prototype), r;
      }
      return t(n, e), n;
    })(Co),
    Uo = (function (e) {
      function n(t) {
        var r = e.call(this, 'cancelled', 'Popup closed') || this;
        return (r.popup = t), Object.setPrototypeOf(r, n.prototype), r;
      }
      return t(n, e), n;
    })(Ro),
    Ao = function (e) {
      return new Promise(function (t, n) {
        var r,
          o = setInterval(function () {
            e.popup &&
              e.popup.closed &&
              (clearInterval(o),
              clearTimeout(i),
              window.removeEventListener('message', r, !1),
              n(new Uo(e.popup)));
          }, 1e3),
          i = setTimeout(function () {
            clearInterval(o),
              n(new jo(e.popup)),
              window.removeEventListener('message', r, !1);
          }, 1e3 * (e.timeoutInSeconds || 60));
        (r = function (a) {
          if (a.data && 'authorization_response' === a.data.type) {
            if (
              (clearTimeout(i),
              clearInterval(o),
              window.removeEventListener('message', r, !1),
              e.popup.close(),
              a.data.response.error)
            )
              return n(Ro.fromPayload(a.data.response));
            t(a.data.response);
          }
        }),
          window.addEventListener('message', r);
      });
    },
    Po = function () {
      return window.crypto || window.msCrypto;
    },
    Fo = function () {
      var e = Po();
      return e.subtle || e.webkitSubtle;
    },
    Ko = function () {
      var e =
          '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_~.',
        t = '';
      return (
        Array.from(Po().getRandomValues(new Uint8Array(43))).forEach(function (
          n
        ) {
          return (t += e[n % e.length]);
        }),
        t
      );
    },
    Wo = function (e) {
      return btoa(e);
    },
    zo = function (e) {
      return Object.keys(e)
        .filter(function (t) {
          return void 0 !== e[t];
        })
        .map(function (t) {
          return encodeURIComponent(t) + '=' + encodeURIComponent(e[t]);
        })
        .join('&');
    },
    Vo = function (e) {
      return o(void 0, void 0, void 0, function () {
        var t;
        return i(this, function (n) {
          switch (n.label) {
            case 0:
              return (
                (t = Fo().digest(
                  { name: 'SHA-256' },
                  new TextEncoder().encode(e)
                )),
                window.msCrypto
                  ? [
                      2,
                      new Promise(function (e, n) {
                        (t.oncomplete = function (t) {
                          e(t.target.result);
                        }),
                          (t.onerror = function (e) {
                            n(e.error);
                          }),
                          (t.onabort = function () {
                            n('The digest operation was aborted');
                          });
                      }),
                    ]
                  : [4, t]
              );
            case 1:
              return [2, n.sent()];
          }
        });
      });
    },
    Zo = function (e) {
      return (function (e) {
        return decodeURIComponent(
          atob(e)
            .split('')
            .map(function (e) {
              return '%' + ('00' + e.charCodeAt(0).toString(16)).slice(-2);
            })
            .join('')
        );
      })(e.replace(/_/g, '/').replace(/-/g, '+'));
    },
    Xo = function (e) {
      var t = new Uint8Array(e);
      return (function (e) {
        var t = { '+': '-', '/': '_', '=': '' };
        return e.replace(/[+/=]/g, function (e) {
          return t[e];
        });
      })(window.btoa(String.fromCharCode.apply(String, Array.from(t))));
    };
  var No = function (e, t) {
      return o(void 0, void 0, void 0, function () {
        var n, r;
        return i(this, function (o) {
          switch (o.label) {
            case 0:
              return [
                4,
                ((i = e),
                (a = t),
                (a = a || {}),
                new Promise(function (e, t) {
                  var n = new XMLHttpRequest(),
                    r = [],
                    o = [],
                    c = {},
                    s = function () {
                      return {
                        ok: 2 == ((n.status / 100) | 0),
                        statusText: n.statusText,
                        status: n.status,
                        url: n.responseURL,
                        text: function () {
                          return Promise.resolve(n.responseText);
                        },
                        json: function () {
                          return Promise.resolve(n.responseText).then(
                            JSON.parse
                          );
                        },
                        blob: function () {
                          return Promise.resolve(new Blob([n.response]));
                        },
                        clone: s,
                        headers: {
                          keys: function () {
                            return r;
                          },
                          entries: function () {
                            return o;
                          },
                          get: function (e) {
                            return c[e.toLowerCase()];
                          },
                          has: function (e) {
                            return e.toLowerCase() in c;
                          },
                        },
                      };
                    };
                  for (var u in (n.open(a.method || 'get', i, !0),
                  (n.onload = function () {
                    n
                      .getAllResponseHeaders()
                      .replace(/^(.*?):[^\S\n]*([\s\S]*?)$/gm, function (
                        e,
                        t,
                        n
                      ) {
                        r.push((t = t.toLowerCase())),
                          o.push([t, n]),
                          (c[t] = c[t] ? c[t] + ',' + n : n);
                      }),
                      e(s());
                  }),
                  (n.onerror = t),
                  (n.withCredentials = 'include' == a.credentials),
                  a.headers))
                    n.setRequestHeader(u, a.headers[u]);
                  n.send(a.body || null);
                })),
              ];
            case 1:
              return (n = o.sent()), (r = { ok: n.ok }), [4, n.json()];
            case 2:
              return [2, ((r.json = o.sent()), r)];
          }
          var i, a;
        });
      });
    },
    Go = function (e, t, n) {
      return o(void 0, void 0, void 0, function () {
        var r, o;
        return i(this, function (i) {
          return (
            (r = new AbortController()),
            (t.signal = r.signal),
            [
              2,
              Promise.race([
                No(e, t),
                new Promise(function (e, t) {
                  o = setTimeout(function () {
                    r.abort(), t(new Error("Timeout when executing 'fetch'"));
                  }, n);
                }),
              ]).finally(function () {
                clearTimeout(o);
              }),
            ]
          );
        });
      });
    },
    Jo = function (e, t, n, r, a, c) {
      return o(void 0, void 0, void 0, function () {
        return i(this, function (o) {
          return [
            2,
            ((i = {
              auth: { audience: t, scope: n },
              timeout: a,
              fetchUrl: e,
              fetchOptions: r,
            }),
            (s = c),
            new Promise(function (e, t) {
              var n = new MessageChannel();
              (n.port1.onmessage = function (n) {
                n.data.error ? t(new Error(n.data.error)) : e(n.data);
              }),
                s.postMessage(i, [n.port2]);
            })),
          ];
          var i, s;
        });
      });
    },
    Do = function (e, t, n, r, a, c) {
      return (
        void 0 === c && (c = 1e4),
        o(void 0, void 0, void 0, function () {
          return i(this, function (o) {
            return a ? [2, Jo(e, t, n, r, c, a)] : [2, Go(e, r, c)];
          });
        })
      );
    };
  function Yo(e, t, n, a, c, s) {
    return o(this, void 0, void 0, function () {
      var o, u, l, f, d, p, h, y;
      return i(this, function (i) {
        switch (i.label) {
          case 0:
            (o = null), (l = 0), (i.label = 1);
          case 1:
            if (!(l < 3)) return [3, 6];
            i.label = 2;
          case 2:
            return i.trys.push([2, 4, , 5]), [4, Do(e, n, a, c, s, t)];
          case 3:
            return (u = i.sent()), (o = null), [3, 6];
          case 4:
            return (f = i.sent()), (o = f), [3, 5];
          case 5:
            return l++, [3, 1];
          case 6:
            if (o) throw ((o.message = o.message || 'Failed to fetch'), o);
            if (
              ((d = u.json),
              (p = d.error),
              (h = d.error_description),
              (y = r(d, ['error', 'error_description'])),
              !u.ok)
            )
              throw new Ro(
                p || 'request_error',
                h || 'HTTP error. Unable to fetch ' + e
              );
            return [2, y];
        }
      });
    });
  }
  function Bo(e, t) {
    var n = e.baseUrl,
      a = e.timeout,
      c = e.audience,
      s = e.scope,
      u = e.auth0Client,
      l = r(e, ['baseUrl', 'timeout', 'audience', 'scope', 'auth0Client']);
    return o(this, void 0, void 0, function () {
      return i(this, function (e) {
        switch (e.label) {
          case 0:
            return [
              4,
              Yo(
                n + '/oauth/token',
                a,
                c || 'default',
                s,
                {
                  method: 'POST',
                  body: JSON.stringify(l),
                  headers: {
                    'Content-type': 'application/json',
                    'Auth0-Client': btoa(JSON.stringify(u || xo)),
                  },
                },
                t
              ),
            ];
          case 1:
            return [2, e.sent()];
        }
      });
    });
  }
  var Mo = function (e) {
      return Array.from(new Set(e));
    },
    qo = function () {
      for (var e = [], t = 0; t < arguments.length; t++) e[t] = arguments[t];
      return Mo(e.join(' ').trim().split(/\s+/)).join(' ');
    },
    Ho = (function () {
      function e(e, t) {
        void 0 === t && (t = Qo),
          (this.prefix = t),
          (this.client_id = e.client_id),
          (this.scope = e.scope),
          (this.audience = e.audience);
      }
      return (
        (e.prototype.toKey = function () {
          return (
            this.prefix +
            '::' +
            this.client_id +
            '::' +
            this.audience +
            '::' +
            this.scope
          );
        }),
        (e.fromKey = function (t) {
          var n = t.split('::'),
            r = n[0],
            o = n[1],
            i = n[2];
          return new e({ client_id: o, scope: n[3], audience: i }, r);
        }),
        e
      );
    })(),
    Qo = '@@auth0spajs@@',
    $o = function (e) {
      var t = Math.floor(Date.now() / 1e3) + e.expires_in;
      return { body: e, expiresAt: Math.min(t, e.decodedToken.claims.exp) };
    },
    ei = function (e, t) {
      var n = e.client_id,
        r = e.audience,
        o = e.scope;
      return t.filter(function (e) {
        var t = Ho.fromKey(e),
          i = t.prefix,
          a = t.client_id,
          c = t.audience,
          s = t.scope,
          u = s && s.split(' '),
          l =
            s &&
            o.split(' ').reduce(function (e, t) {
              return e && u.includes(t);
            }, !0);
        return i === Qo && a === n && c === r && l;
      })[0];
    },
    ti = (function () {
      function e() {}
      return (
        (e.prototype.save = function (e) {
          var t = new Ho({
              client_id: e.client_id,
              scope: e.scope,
              audience: e.audience,
            }),
            n = $o(e);
          window.localStorage.setItem(t.toKey(), JSON.stringify(n));
        }),
        (e.prototype.get = function (e, t) {
          void 0 === t && (t = 0);
          var n = this.readJson(e),
            r = Math.floor(Date.now() / 1e3);
          if (n) {
            if (!(n.expiresAt - t < r)) return n.body;
            if (n.body.refresh_token) {
              var o = this.stripData(n);
              return this.writeJson(e.toKey(), o), o.body;
            }
            localStorage.removeItem(e.toKey());
          }
        }),
        (e.prototype.clear = function () {
          for (var e = localStorage.length - 1; e >= 0; e--)
            localStorage.key(e).startsWith(Qo) &&
              localStorage.removeItem(localStorage.key(e));
        }),
        (e.prototype.readJson = function (e) {
          var t,
            n = ei(e, Object.keys(window.localStorage)),
            r = n && window.localStorage.getItem(n);
          if (r && (t = JSON.parse(r))) return t;
        }),
        (e.prototype.writeJson = function (e, t) {
          localStorage.setItem(e, JSON.stringify(t));
        }),
        (e.prototype.stripData = function (e) {
          return {
            body: { refresh_token: e.body.refresh_token },
            expiresAt: e.expiresAt,
          };
        }),
        e
      );
    })(),
    ni = function () {
      var e;
      this.enclosedCache =
        ((e = {}),
        {
          save: function (t) {
            var n = new Ho({
                client_id: t.client_id,
                scope: t.scope,
                audience: t.audience,
              }),
              r = $o(t);
            e[n.toKey()] = r;
          },
          get: function (t, n) {
            void 0 === n && (n = 0);
            var r = ei(t, Object.keys(e)),
              o = e[r],
              i = Math.floor(Date.now() / 1e3);
            if (o)
              return o.expiresAt - n < i
                ? o.body.refresh_token
                  ? ((o.body = { refresh_token: o.body.refresh_token }), o.body)
                  : void delete e[t.toKey()]
                : o.body;
          },
          clear: function () {
            e = {};
          },
        });
    },
    ri = (function () {
      function e(e) {
        (this.storage = e),
          (this.transaction = this.storage.get('a0.spajs.txs'));
      }
      return (
        (e.prototype.create = function (e) {
          (this.transaction = e),
            this.storage.save('a0.spajs.txs', e, { daysUntilExpire: 1 });
        }),
        (e.prototype.get = function () {
          return this.transaction;
        }),
        (e.prototype.remove = function () {
          delete this.transaction, this.storage.remove('a0.spajs.txs');
        }),
        e
      );
    })(),
    oi = function (e) {
      return 'number' == typeof e;
    },
    ii = [
      'iss',
      'aud',
      'exp',
      'nbf',
      'iat',
      'jti',
      'azp',
      'nonce',
      'auth_time',
      'at_hash',
      'c_hash',
      'acr',
      'amr',
      'sub_jwk',
      'cnf',
      'sip_from_tag',
      'sip_date',
      'sip_callid',
      'sip_cseq_num',
      'sip_via_branch',
      'orig',
      'dest',
      'mky',
      'events',
      'toe',
      'txn',
      'rph',
      'sid',
      'vot',
      'vtm',
    ],
    ai = function (e) {
      if (!e.id_token) throw new Error('ID token is required but missing');
      var t = (function (e) {
        var t = e.split('.'),
          n = t[0],
          r = t[1],
          o = t[2];
        if (3 !== t.length || !n || !r || !o)
          throw new Error('ID token could not be decoded');
        var i = JSON.parse(Zo(r)),
          a = { __raw: e },
          c = {};
        return (
          Object.keys(i).forEach(function (e) {
            (a[e] = i[e]), ii.includes(e) || (c[e] = i[e]);
          }),
          {
            encoded: { header: n, payload: r, signature: o },
            header: JSON.parse(Zo(n)),
            claims: a,
            user: c,
          }
        );
      })(e.id_token);
      if (!t.claims.iss)
        throw new Error(
          'Issuer (iss) claim must be a string present in the ID token'
        );
      if (t.claims.iss !== e.iss)
        throw new Error(
          'Issuer (iss) claim mismatch in the ID token; expected "' +
            e.iss +
            '", found "' +
            t.claims.iss +
            '"'
        );
      if (!t.user.sub)
        throw new Error(
          'Subject (sub) claim must be a string present in the ID token'
        );
      if ('RS256' !== t.header.alg)
        throw new Error(
          'Signature algorithm of "' +
            t.header.alg +
            '" is not supported. Expected the ID token to be signed with "RS256".'
        );
      if (
        !t.claims.aud ||
        ('string' != typeof t.claims.aud && !Array.isArray(t.claims.aud))
      )
        throw new Error(
          'Audience (aud) claim must be a string or array of strings present in the ID token'
        );
      if (Array.isArray(t.claims.aud)) {
        if (!t.claims.aud.includes(e.aud))
          throw new Error(
            'Audience (aud) claim mismatch in the ID token; expected "' +
              e.aud +
              '" but was not one of "' +
              t.claims.aud.join(', ') +
              '"'
          );
        if (t.claims.aud.length > 1) {
          if (!t.claims.azp)
            throw new Error(
              'Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values'
            );
          if (t.claims.azp !== e.aud)
            throw new Error(
              'Authorized Party (azp) claim mismatch in the ID token; expected "' +
                e.aud +
                '", found "' +
                t.claims.azp +
                '"'
            );
        }
      } else if (t.claims.aud !== e.aud)
        throw new Error(
          'Audience (aud) claim mismatch in the ID token; expected "' +
            e.aud +
            '" but found "' +
            t.claims.aud +
            '"'
        );
      if (e.nonce) {
        if (!t.claims.nonce)
          throw new Error(
            'Nonce (nonce) claim must be a string present in the ID token'
          );
        if (t.claims.nonce !== e.nonce)
          throw new Error(
            'Nonce (nonce) claim mismatch in the ID token; expected "' +
              e.nonce +
              '", found "' +
              t.claims.nonce +
              '"'
          );
      }
      if (e.max_age && !oi(t.claims.auth_time))
        throw new Error(
          'Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified'
        );
      if (!oi(t.claims.exp))
        throw new Error(
          'Expiration Time (exp) claim must be a number present in the ID token'
        );
      if (!oi(t.claims.iat))
        throw new Error(
          'Issued At (iat) claim must be a number present in the ID token'
        );
      var n = e.leeway || 60,
        r = new Date(Date.now()),
        o = new Date(0),
        i = new Date(0),
        a = new Date(0);
      if (
        (a.setUTCSeconds(parseInt(t.claims.auth_time) + e.max_age + n),
        o.setUTCSeconds(t.claims.exp + n),
        i.setUTCSeconds(t.claims.nbf - n),
        r > o)
      )
        throw new Error(
          'Expiration Time (exp) claim error in the ID token; current time (' +
            r +
            ') is after expiration time (' +
            o +
            ')'
        );
      if (oi(t.claims.nbf) && r < i)
        throw new Error(
          "Not Before time (nbf) claim in the ID token indicates that this token can't be used just yet. Currrent time (" +
            r +
            ') is before ' +
            i
        );
      if (oi(t.claims.auth_time) && r > a)
        throw new Error(
          'Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Currrent time (' +
            r +
            ') is after last auth at ' +
            a
        );
      if (e.organizationId) {
        if (!t.claims.org_id)
          throw new Error(
            'Organization ID (org_id) claim must be a string present in the ID token'
          );
        if (e.organizationId !== t.claims.org_id)
          throw new Error(
            'Organization ID (org_id) claim mismatch in the ID token; expected "' +
              e.organizationId +
              '", found "' +
              t.claims.org_id +
              '"'
          );
      }
      return t;
    },
    ci = s(function (e, t) {
      var n =
        (a && a.__assign) ||
        function () {
          return (n =
            Object.assign ||
            function (e) {
              for (var t, n = 1, r = arguments.length; n < r; n++)
                for (var o in (t = arguments[n]))
                  Object.prototype.hasOwnProperty.call(t, o) && (e[o] = t[o]);
              return e;
            }).apply(this, arguments);
        };
      function r(e, t) {
        if (!t) return '';
        var n = '; ' + e;
        return !0 === t ? n : n + '=' + t;
      }
      function o(e, t, n) {
        return (
          encodeURIComponent(e)
            .replace(/%(23|24|26|2B|5E|60|7C)/g, decodeURIComponent)
            .replace(/\(/g, '%28')
            .replace(/\)/g, '%29') +
          '=' +
          encodeURIComponent(t).replace(
            /%(23|24|26|2B|3A|3C|3E|3D|2F|3F|40|5B|5D|5E|60|7B|7D|7C)/g,
            decodeURIComponent
          ) +
          (function (e) {
            if ('number' == typeof e.expires) {
              var t = new Date();
              t.setMilliseconds(t.getMilliseconds() + 864e5 * e.expires),
                (e.expires = t);
            }
            return (
              r('Expires', e.expires ? e.expires.toUTCString() : '') +
              r('Domain', e.domain) +
              r('Path', e.path) +
              r('Secure', e.secure) +
              r('SameSite', e.sameSite)
            );
          })(n)
        );
      }
      function i(e) {
        for (
          var t = {}, n = e ? e.split('; ') : [], r = /(%[\dA-F]{2})+/gi, o = 0;
          o < n.length;
          o++
        ) {
          var i = n[o].split('='),
            a = i.slice(1).join('=');
          '"' === a.charAt(0) && (a = a.slice(1, -1));
          try {
            t[i[0].replace(r, decodeURIComponent)] = a.replace(
              r,
              decodeURIComponent
            );
          } catch (e) {}
        }
        return t;
      }
      function c() {
        return i(document.cookie);
      }
      function s(e, t, r) {
        document.cookie = o(e, t, n({ path: '/' }, r));
      }
      (t.__esModule = !0),
        (t.encode = o),
        (t.parse = i),
        (t.getAll = c),
        (t.get = function (e) {
          return c()[e];
        }),
        (t.set = s),
        (t.remove = function (e, t) {
          s(e, '', n(n({}, t), { expires: -1 }));
        });
    });
  c(ci), ci.encode, ci.parse, ci.getAll;
  var si = ci.get,
    ui = ci.set,
    li = ci.remove,
    fi = {
      get: function (e) {
        var t = si(e);
        if (void 0 !== t) return JSON.parse(t);
      },
      save: function (e, t, n) {
        var r = {};
        'https:' === window.location.protocol &&
          (r = { secure: !0, sameSite: 'none' }),
          (r.expires = n.daysUntilExpire),
          ui(e, JSON.stringify(t), r);
      },
      remove: function (e) {
        li(e);
      },
    },
    di = {
      get: function (e) {
        var t = fi.get(e);
        return t || fi.get('_legacy_' + e);
      },
      save: function (e, t, n) {
        var r = {};
        'https:' === window.location.protocol && (r = { secure: !0 }),
          (r.expires = n.daysUntilExpire),
          ui('_legacy_' + e, JSON.stringify(t), r),
          fi.save(e, t, n);
      },
      remove: function (e) {
        fi.remove(e), fi.remove('_legacy_' + e);
      },
    },
    pi = {
      get: function (e) {
        if ('undefined' != typeof sessionStorage) {
          var t = sessionStorage.getItem(e);
          if (void 0 !== t) return JSON.parse(t);
        }
      },
      save: function (e, t) {
        sessionStorage.setItem(e, JSON.stringify(t));
      },
      remove: function (e) {
        sessionStorage.removeItem(e);
      },
    };
  function hi(e, t, n) {
    var r = void 0 === t ? null : t,
      o = (function (e, t) {
        var n = atob(e);
        if (t) {
          for (
            var r = new Uint8Array(n.length), o = 0, i = n.length;
            o < i;
            ++o
          )
            r[o] = n.charCodeAt(o);
          return String.fromCharCode.apply(null, new Uint16Array(r.buffer));
        }
        return n;
      })(e, void 0 !== n && n),
      i = o.indexOf('\n', 10) + 1,
      a = o.substring(i) + (r ? '//# sourceMappingURL=' + r : ''),
      c = new Blob([a], { type: 'application/javascript' });
    return URL.createObjectURL(c);
  }
  var yi,
    vi,
    mi,
    gi,
    bi =
      ((yi =
        'Lyogcm9sbHVwLXBsdWdpbi13ZWItd29ya2VyLWxvYWRlciAqLwohZnVuY3Rpb24oKXsidXNlIHN0cmljdCI7Ci8qISAqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKgogICAgQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uCgogICAgUGVybWlzc2lvbiB0byB1c2UsIGNvcHksIG1vZGlmeSwgYW5kL29yIGRpc3RyaWJ1dGUgdGhpcyBzb2Z0d2FyZSBmb3IgYW55CiAgICBwdXJwb3NlIHdpdGggb3Igd2l0aG91dCBmZWUgaXMgaGVyZWJ5IGdyYW50ZWQuCgogICAgVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEICJBUyBJUyIgQU5EIFRIRSBBVVRIT1IgRElTQ0xBSU1TIEFMTCBXQVJSQU5USUVTIFdJVEgKICAgIFJFR0FSRCBUTyBUSElTIFNPRlRXQVJFIElOQ0xVRElORyBBTEwgSU1QTElFRCBXQVJSQU5USUVTIE9GIE1FUkNIQU5UQUJJTElUWQogICAgQU5EIEZJVE5FU1MuIElOIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1IgQkUgTElBQkxFIEZPUiBBTlkgU1BFQ0lBTCwgRElSRUNULAogICAgSU5ESVJFQ1QsIE9SIENPTlNFUVVFTlRJQUwgREFNQUdFUyBPUiBBTlkgREFNQUdFUyBXSEFUU09FVkVSIFJFU1VMVElORyBGUk9NCiAgICBMT1NTIE9GIFVTRSwgREFUQSBPUiBQUk9GSVRTLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgTkVHTElHRU5DRSBPUgogICAgT1RIRVIgVE9SVElPVVMgQUNUSU9OLCBBUklTSU5HIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFVTRSBPUgogICAgUEVSRk9STUFOQ0UgT0YgVEhJUyBTT0ZUV0FSRS4KICAgICoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqICovdmFyIGU9ZnVuY3Rpb24oKXtyZXR1cm4oZT1PYmplY3QuYXNzaWdufHxmdW5jdGlvbihlKXtmb3IodmFyIHQscj0xLG49YXJndW1lbnRzLmxlbmd0aDtyPG47cisrKWZvcih2YXIgbyBpbiB0PWFyZ3VtZW50c1tyXSlPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwodCxvKSYmKGVbb109dFtvXSk7cmV0dXJuIGV9KS5hcHBseSh0aGlzLGFyZ3VtZW50cyl9O2Z1bmN0aW9uIHQoZSx0LHIsbil7cmV0dXJuIG5ldyhyfHwocj1Qcm9taXNlKSkoKGZ1bmN0aW9uKG8scyl7ZnVuY3Rpb24gYShlKXt0cnl7dShuLm5leHQoZSkpfWNhdGNoKGUpe3MoZSl9fWZ1bmN0aW9uIGkoZSl7dHJ5e3Uobi50aHJvdyhlKSl9Y2F0Y2goZSl7cyhlKX19ZnVuY3Rpb24gdShlKXt2YXIgdDtlLmRvbmU/byhlLnZhbHVlKToodD1lLnZhbHVlLHQgaW5zdGFuY2VvZiByP3Q6bmV3IHIoKGZ1bmN0aW9uKGUpe2UodCl9KSkpLnRoZW4oYSxpKX11KChuPW4uYXBwbHkoZSx0fHxbXSkpLm5leHQoKSl9KSl9ZnVuY3Rpb24gcihlLHQpe3ZhciByLG4sbyxzLGE9e2xhYmVsOjAsc2VudDpmdW5jdGlvbigpe2lmKDEmb1swXSl0aHJvdyBvWzFdO3JldHVybiBvWzFdfSx0cnlzOltdLG9wczpbXX07cmV0dXJuIHM9e25leHQ6aSgwKSx0aHJvdzppKDEpLHJldHVybjppKDIpfSwiZnVuY3Rpb24iPT10eXBlb2YgU3ltYm9sJiYoc1tTeW1ib2wuaXRlcmF0b3JdPWZ1bmN0aW9uKCl7cmV0dXJuIHRoaXN9KSxzO2Z1bmN0aW9uIGkocyl7cmV0dXJuIGZ1bmN0aW9uKGkpe3JldHVybiBmdW5jdGlvbihzKXtpZihyKXRocm93IG5ldyBUeXBlRXJyb3IoIkdlbmVyYXRvciBpcyBhbHJlYWR5IGV4ZWN1dGluZy4iKTtmb3IoO2E7KXRyeXtpZihyPTEsbiYmKG89MiZzWzBdP24ucmV0dXJuOnNbMF0/bi50aHJvd3x8KChvPW4ucmV0dXJuKSYmby5jYWxsKG4pLDApOm4ubmV4dCkmJiEobz1vLmNhbGwobixzWzFdKSkuZG9uZSlyZXR1cm4gbztzd2l0Y2gobj0wLG8mJihzPVsyJnNbMF0sby52YWx1ZV0pLHNbMF0pe2Nhc2UgMDpjYXNlIDE6bz1zO2JyZWFrO2Nhc2UgNDpyZXR1cm4gYS5sYWJlbCsrLHt2YWx1ZTpzWzFdLGRvbmU6ITF9O2Nhc2UgNTphLmxhYmVsKyssbj1zWzFdLHM9WzBdO2NvbnRpbnVlO2Nhc2UgNzpzPWEub3BzLnBvcCgpLGEudHJ5cy5wb3AoKTtjb250aW51ZTtkZWZhdWx0OmlmKCEobz1hLnRyeXMsKG89by5sZW5ndGg+MCYmb1tvLmxlbmd0aC0xXSl8fDYhPT1zWzBdJiYyIT09c1swXSkpe2E9MDtjb250aW51ZX1pZigzPT09c1swXSYmKCFvfHxzWzFdPm9bMF0mJnNbMV08b1szXSkpe2EubGFiZWw9c1sxXTticmVha31pZig2PT09c1swXSYmYS5sYWJlbDxvWzFdKXthLmxhYmVsPW9bMV0sbz1zO2JyZWFrfWlmKG8mJmEubGFiZWw8b1syXSl7YS5sYWJlbD1vWzJdLGEub3BzLnB1c2gocyk7YnJlYWt9b1syXSYmYS5vcHMucG9wKCksYS50cnlzLnBvcCgpO2NvbnRpbnVlfXM9dC5jYWxsKGUsYSl9Y2F0Y2goZSl7cz1bNixlXSxuPTB9ZmluYWxseXtyPW89MH1pZig1JnNbMF0pdGhyb3cgc1sxXTtyZXR1cm57dmFsdWU6c1swXT9zWzFdOnZvaWQgMCxkb25lOiEwfX0oW3MsaV0pfX19dmFyIG49e30sbz1mdW5jdGlvbihlLHQpe3JldHVybiBlKyJ8Iit0fTthZGRFdmVudExpc3RlbmVyKCJtZXNzYWdlIiwoZnVuY3Rpb24ocyl7dmFyIGE9cy5kYXRhLGk9YS50aW1lb3V0LHU9YS5hdXRoLGM9YS5mZXRjaFVybCxmPWEuZmV0Y2hPcHRpb25zLGw9cy5wb3J0c1swXTtyZXR1cm4gdCh2b2lkIDAsdm9pZCAwLHZvaWQgMCwoZnVuY3Rpb24oKXt2YXIgdCxzLGEsaCxwLGIseSxkLHYsdztyZXR1cm4gcih0aGlzLChmdW5jdGlvbihyKXtzd2l0Y2goci5sYWJlbCl7Y2FzZSAwOmE9KHM9dXx8e30pLmF1ZGllbmNlLGg9cy5zY29wZSxyLmxhYmVsPTE7Y2FzZSAxOmlmKHIudHJ5cy5wdXNoKFsxLDcsLDhdKSwhKHA9SlNPTi5wYXJzZShmLmJvZHkpKS5yZWZyZXNoX3Rva2VuJiYicmVmcmVzaF90b2tlbiI9PT1wLmdyYW50X3R5cGUpe2lmKCEoYj1mdW5jdGlvbihlLHQpe3JldHVybiBuW28oZSx0KV19KGEsaCkpKXRocm93IG5ldyBFcnJvcigiVGhlIHdlYiB3b3JrZXIgaXMgbWlzc2luZyB0aGUgcmVmcmVzaCB0b2tlbiIpO2YuYm9keT1KU09OLnN0cmluZ2lmeShlKGUoe30scCkse3JlZnJlc2hfdG9rZW46Yn0pKX15PXZvaWQgMCwiZnVuY3Rpb24iPT10eXBlb2YgQWJvcnRDb250cm9sbGVyJiYoeT1uZXcgQWJvcnRDb250cm9sbGVyLGYuc2lnbmFsPXkuc2lnbmFsKSxkPXZvaWQgMCxyLmxhYmVsPTI7Y2FzZSAyOnJldHVybiByLnRyeXMucHVzaChbMiw0LCw1XSksWzQsUHJvbWlzZS5yYWNlKFsoZz1pLG5ldyBQcm9taXNlKChmdW5jdGlvbihlKXtyZXR1cm4gc2V0VGltZW91dChlLGcpfSkpKSxmZXRjaChjLGUoe30sZikpXSldO2Nhc2UgMzpyZXR1cm4gZD1yLnNlbnQoKSxbMyw1XTtjYXNlIDQ6cmV0dXJuIHY9ci5zZW50KCksbC5wb3N0TWVzc2FnZSh7ZXJyb3I6di5tZXNzYWdlfSksWzJdO2Nhc2UgNTpyZXR1cm4gZD9bNCxkLmpzb24oKV06KHkmJnkuYWJvcnQoKSxsLnBvc3RNZXNzYWdlKHtlcnJvcjoiVGltZW91dCB3aGVuIGV4ZWN1dGluZyAnZmV0Y2gnIn0pLFsyXSk7Y2FzZSA2OnJldHVybih0PXIuc2VudCgpKS5yZWZyZXNoX3Rva2VuPyhmdW5jdGlvbihlLHQscil7bltvKHQscildPWV9KHQucmVmcmVzaF90b2tlbixhLGgpLGRlbGV0ZSB0LnJlZnJlc2hfdG9rZW4pOmZ1bmN0aW9uKGUsdCl7ZGVsZXRlIG5bbyhlLHQpXX0oYSxoKSxsLnBvc3RNZXNzYWdlKHtvazpkLm9rLGpzb246dH0pLFszLDhdO2Nhc2UgNzpyZXR1cm4gdz1yLnNlbnQoKSxsLnBvc3RNZXNzYWdlKHtvazohMSxqc29uOntlcnJvcl9kZXNjcmlwdGlvbjp3Lm1lc3NhZ2V9fSksWzMsOF07Y2FzZSA4OnJldHVyblsyXX12YXIgZ30pKX0pKX0pKX0oKTsKCg=='),
      (vi = null),
      (mi = !1),
      function (e) {
        return (gi = gi || hi(yi, vi, mi)), new Worker(gi, e);
      }),
    wi = {},
    Si = new To(),
    _i = {
      memory: function () {
        return new ni().enclosedCache;
      },
      localstorage: function () {
        return new ti();
      },
    },
    ki = function (e) {
      return _i[e];
    },
    Ii = function () {
      return !/Trident.*rv:11\.0/.test(navigator.userAgent);
    },
    Ti = (function () {
      function e(e) {
        var t, n;
        if (
          ((this.options = e),
          'undefined' != typeof window &&
            (function () {
              if (!Po())
                throw new Error(
                  'For security reasons, `window.crypto` is required to run `auth0-spa-js`.'
                );
              if (void 0 === Fo())
                throw new Error(
                  '\n      auth0-spa-js must run on a secure origin. See https://github.com/auth0/auth0-spa-js/blob/master/FAQ.md#why-do-i-get-auth0-spa-js-must-run-on-a-secure-origin for more information.\n    '
                );
            })(),
          (this.cacheLocation = e.cacheLocation || 'memory'),
          (this.cookieStorage = !1 === e.legacySameSiteCookie ? fi : di),
          (this.sessionCheckExpiryDays = e.sessionCheckExpiryDays || 1),
          !ki(this.cacheLocation))
        )
          throw new Error(
            'Invalid cache location "' + this.cacheLocation + '"'
          );
        var o,
          i,
          a = e.useCookiesForTransactions ? this.cookieStorage : pi;
        (this.cache = ki(this.cacheLocation)()),
          (this.scope = this.options.scope),
          (this.transactionManager = new ri(a)),
          (this.domainUrl = 'https://' + this.options.domain),
          (this.tokenIssuer =
            ((o = this.options.issuer),
            (i = this.domainUrl),
            o
              ? o.startsWith('https://')
                ? o
                : 'https://' + o + '/'
              : i + '/')),
          (this.defaultScope = qo(
            'openid',
            void 0 !==
              (null ===
                (n =
                  null === (t = this.options) || void 0 === t
                    ? void 0
                    : t.advancedOptions) || void 0 === n
                ? void 0
                : n.defaultScope)
              ? this.options.advancedOptions.defaultScope
              : 'openid profile email'
          )),
          this.options.useRefreshTokens &&
            (this.scope = qo(this.scope, 'offline_access')),
          'undefined' != typeof window &&
            window.Worker &&
            this.options.useRefreshTokens &&
            'memory' === this.cacheLocation &&
            Ii() &&
            (this.worker = new bi()),
          (this.customOptions = (function (e) {
            return (
              e.advancedOptions,
              e.audience,
              e.auth0Client,
              e.authorizeTimeoutInSeconds,
              e.cacheLocation,
              e.client_id,
              e.domain,
              e.issuer,
              e.leeway,
              e.max_age,
              e.redirect_uri,
              e.scope,
              e.useRefreshTokens,
              r(e, [
                'advancedOptions',
                'audience',
                'auth0Client',
                'authorizeTimeoutInSeconds',
                'cacheLocation',
                'client_id',
                'domain',
                'issuer',
                'leeway',
                'max_age',
                'redirect_uri',
                'scope',
                'useRefreshTokens',
              ])
            );
          })(e));
      }
      return (
        (e.prototype._url = function (e) {
          var t = encodeURIComponent(
            btoa(JSON.stringify(this.options.auth0Client || xo))
          );
          return '' + this.domainUrl + e + '&auth0Client=' + t;
        }),
        (e.prototype._getParams = function (e, t, o, i, a) {
          var c = this.options;
          c.domain,
            c.leeway,
            c.useRefreshTokens,
            c.useCookiesForTransactions,
            c.auth0Client,
            c.cacheLocation,
            c.advancedOptions;
          var s = r(c, [
            'domain',
            'leeway',
            'useRefreshTokens',
            'useCookiesForTransactions',
            'auth0Client',
            'cacheLocation',
            'advancedOptions',
          ]);
          return n(n(n({}, s), e), {
            scope: qo(this.defaultScope, this.scope, e.scope),
            response_type: 'code',
            response_mode: 'query',
            state: t,
            nonce: o,
            redirect_uri: a || this.options.redirect_uri,
            code_challenge: i,
            code_challenge_method: 'S256',
          });
        }),
        (e.prototype._authorizeUrl = function (e) {
          return this._url('/authorize?' + zo(e));
        }),
        (e.prototype._verifyIdToken = function (e, t, n) {
          return ai({
            iss: this.tokenIssuer,
            aud: this.options.client_id,
            id_token: e,
            nonce: t,
            organizationId: n,
            leeway: this.options.leeway,
            max_age: this._parseNumber(this.options.max_age),
          });
        }),
        (e.prototype._parseNumber = function (e) {
          return 'string' != typeof e ? e : parseInt(e, 10) || void 0;
        }),
        (e.prototype.buildAuthorizeUrl = function (e) {
          return (
            void 0 === e && (e = {}),
            o(this, void 0, void 0, function () {
              var t, o, a, c, s, u, l, f, d, p, h, y;
              return i(this, function (i) {
                switch (i.label) {
                  case 0:
                    return (
                      (t = e.redirect_uri),
                      (o = e.appState),
                      (a = r(e, ['redirect_uri', 'appState'])),
                      (c = Wo(Ko())),
                      (s = Wo(Ko())),
                      (u = Ko()),
                      [4, Vo(u)]
                    );
                  case 1:
                    return (
                      (l = i.sent()),
                      (f = Xo(l)),
                      (d = e.fragment ? '#' + e.fragment : ''),
                      (p = this._getParams(a, c, s, f, t)),
                      (h = this._authorizeUrl(p)),
                      (y = e.organization || this.options.organization),
                      this.transactionManager.create(
                        n(
                          {
                            nonce: s,
                            code_verifier: u,
                            appState: o,
                            scope: p.scope,
                            audience: p.audience || 'default',
                            redirect_uri: p.redirect_uri,
                          },
                          y && { organizationId: y }
                        )
                      ),
                      [2, h + d]
                    );
                }
              });
            })
          );
        }),
        (e.prototype.loginWithPopup = function (e, t) {
          return o(this, void 0, void 0, function () {
            var o, a, c, s, u, l, f, d, p, h, y, v, m;
            return i(this, function (i) {
              switch (i.label) {
                case 0:
                  return (
                    (e = e || {}),
                    (t = t || {}).popup ||
                      (t.popup = (function (e) {
                        var t = window.screenX + (window.innerWidth - 400) / 2,
                          n = window.screenY + (window.innerHeight - 600) / 2;
                        return window.open(
                          e,
                          'auth0:authorize:popup',
                          'left=' +
                            t +
                            ',top=' +
                            n +
                            ',width=400,height=600,resizable,scrollbars=yes,status=1'
                        );
                      })('')),
                    (o = r(e, [])),
                    (a = Wo(Ko())),
                    (c = Wo(Ko())),
                    (s = Ko()),
                    [4, Vo(s)]
                  );
                case 1:
                  return (
                    (u = i.sent()),
                    (l = Xo(u)),
                    (f = this._getParams(
                      o,
                      a,
                      c,
                      l,
                      this.options.redirect_uri || window.location.origin
                    )),
                    (d = this._authorizeUrl(
                      n(n({}, f), { response_mode: 'web_message' })
                    )),
                    (t.popup.location.href = d),
                    [
                      4,
                      Ao(
                        n(n({}, t), {
                          timeoutInSeconds:
                            t.timeoutInSeconds ||
                            this.options.authorizeTimeoutInSeconds ||
                            60,
                        })
                      ),
                    ]
                  );
                case 2:
                  if (((p = i.sent()), a !== p.state))
                    throw new Error('Invalid state');
                  return [
                    4,
                    Bo(
                      {
                        audience: f.audience,
                        scope: f.scope,
                        baseUrl: this.domainUrl,
                        client_id: this.options.client_id,
                        code_verifier: s,
                        code: p.code,
                        grant_type: 'authorization_code',
                        redirect_uri: f.redirect_uri,
                        auth0Client: this.options.auth0Client,
                      },
                      this.worker
                    ),
                  ];
                case 3:
                  return (
                    (h = i.sent()),
                    (y = e.organization || this.options.organization),
                    (v = this._verifyIdToken(h.id_token, c, y)),
                    (m = n(n({}, h), {
                      decodedToken: v,
                      scope: f.scope,
                      audience: f.audience || 'default',
                      client_id: this.options.client_id,
                    })),
                    this.cache.save(m),
                    this.cookieStorage.save('auth0.is.authenticated', !0, {
                      daysUntilExpire: this.sessionCheckExpiryDays,
                    }),
                    [2]
                  );
              }
            });
          });
        }),
        (e.prototype.getUser = function (e) {
          return (
            void 0 === e && (e = {}),
            o(this, void 0, void 0, function () {
              var t, n, r;
              return i(this, function (o) {
                return (
                  (t = e.audience || this.options.audience || 'default'),
                  (n = qo(this.defaultScope, this.scope, e.scope)),
                  [
                    2,
                    (r = this.cache.get(
                      new Ho({
                        client_id: this.options.client_id,
                        audience: t,
                        scope: n,
                      })
                    )) &&
                      r.decodedToken &&
                      r.decodedToken.user,
                  ]
                );
              });
            })
          );
        }),
        (e.prototype.getIdTokenClaims = function (e) {
          return (
            void 0 === e && (e = {}),
            o(this, void 0, void 0, function () {
              var t, n, r;
              return i(this, function (o) {
                return (
                  (t = e.audience || this.options.audience || 'default'),
                  (n = qo(this.defaultScope, this.scope, e.scope)),
                  [
                    2,
                    (r = this.cache.get(
                      new Ho({
                        client_id: this.options.client_id,
                        audience: t,
                        scope: n,
                      })
                    )) &&
                      r.decodedToken &&
                      r.decodedToken.claims,
                  ]
                );
              });
            })
          );
        }),
        (e.prototype.loginWithRedirect = function (e) {
          return (
            void 0 === e && (e = {}),
            o(this, void 0, void 0, function () {
              var t, n, o;
              return i(this, function (i) {
                switch (i.label) {
                  case 0:
                    return (
                      (t = e.redirectMethod),
                      (n = r(e, ['redirectMethod'])),
                      [4, this.buildAuthorizeUrl(n)]
                    );
                  case 1:
                    return (
                      (o = i.sent()), window.location[t || 'assign'](o), [2]
                    );
                }
              });
            })
          );
        }),
        (e.prototype.handleRedirectCallback = function (e) {
          return (
            void 0 === e && (e = window.location.href),
            o(this, void 0, void 0, function () {
              var t, r, o, a, c, s, u, l, f, d, p;
              return i(this, function (i) {
                switch (i.label) {
                  case 0:
                    if (0 === (t = e.split('?').slice(1)).length)
                      throw new Error(
                        'There are no query params available for parsing.'
                      );
                    if (
                      ((r = (function (e) {
                        e.indexOf('#') > -1 &&
                          (e = e.substr(0, e.indexOf('#')));
                        var t = e.split('&'),
                          r = {};
                        return (
                          t.forEach(function (e) {
                            var t = e.split('='),
                              n = t[0],
                              o = t[1];
                            r[n] = decodeURIComponent(o);
                          }),
                          n(n({}, r), { expires_in: parseInt(r.expires_in) })
                        );
                      })(t.join(''))),
                      (o = r.state),
                      (a = r.code),
                      (c = r.error),
                      (s = r.error_description),
                      !(u = this.transactionManager.get()) || !u.code_verifier)
                    )
                      throw new Error('Invalid state');
                    if ((this.transactionManager.remove(), c))
                      throw new Lo(c, s, o, u.appState);
                    return (
                      (l = {
                        audience: u.audience,
                        scope: u.scope,
                        baseUrl: this.domainUrl,
                        client_id: this.options.client_id,
                        code_verifier: u.code_verifier,
                        grant_type: 'authorization_code',
                        code: a,
                        auth0Client: this.options.auth0Client,
                      }),
                      void 0 !== u.redirect_uri &&
                        (l.redirect_uri = u.redirect_uri),
                      [4, Bo(l, this.worker)]
                    );
                  case 1:
                    return (
                      (f = i.sent()),
                      (d = this._verifyIdToken(
                        f.id_token,
                        u.nonce,
                        u.organizationId
                      )),
                      (p = n(n({}, f), {
                        decodedToken: d,
                        audience: u.audience,
                        scope: u.scope,
                        client_id: this.options.client_id,
                      })),
                      this.cache.save(p),
                      this.cookieStorage.save('auth0.is.authenticated', !0, {
                        daysUntilExpire: this.sessionCheckExpiryDays,
                      }),
                      [2, { appState: u.appState }]
                    );
                }
              });
            })
          );
        }),
        (e.prototype.checkSession = function (e) {
          return o(this, void 0, void 0, function () {
            var t;
            return i(this, function (n) {
              switch (n.label) {
                case 0:
                  if (!this.cookieStorage.get('auth0.is.authenticated'))
                    return [2];
                  n.label = 1;
                case 1:
                  return (
                    n.trys.push([1, 3, , 4]), [4, this.getTokenSilently(e)]
                  );
                case 2:
                  return n.sent(), [3, 4];
                case 3:
                  if (((t = n.sent()), !Eo.includes(t.error))) throw t;
                  return [3, 4];
                case 4:
                  return [2];
              }
            });
          });
        }),
        (e.prototype.getTokenSilently = function (e) {
          return (
            void 0 === e && (e = {}),
            o(this, void 0, void 0, function () {
              var t,
                o,
                a,
                c = this;
              return i(this, function (i) {
                return (
                  (t = n(
                    n({ audience: this.options.audience, ignoreCache: !1 }, e),
                    { scope: qo(this.defaultScope, this.scope, e.scope) }
                  )),
                  (o = t.ignoreCache),
                  (a = r(t, ['ignoreCache'])),
                  [
                    2,
                    ((s = function () {
                      return c._getTokenSilently(n({ ignoreCache: o }, a));
                    }),
                    (u =
                      this.options.client_id +
                      '::' +
                      a.audience +
                      '::' +
                      a.scope),
                    (l = wi[u]),
                    l ||
                      ((l = s().finally(function () {
                        delete wi[u], (l = null);
                      })),
                      (wi[u] = l)),
                    l),
                  ]
                );
                var s, u, l;
              });
            })
          );
        }),
        (e.prototype._getTokenSilently = function (e) {
          return (
            void 0 === e && (e = {}),
            o(this, void 0, void 0, function () {
              var t,
                a,
                c,
                s,
                u,
                l,
                f = this;
              return i(this, function (d) {
                switch (d.label) {
                  case 0:
                    return (
                      (t = e.ignoreCache),
                      (a = r(e, ['ignoreCache'])),
                      (c = function () {
                        var e = f.cache.get(
                          new Ho({
                            scope: a.scope,
                            audience: a.audience || 'default',
                            client_id: f.options.client_id,
                          }),
                          60
                        );
                        return e && e.access_token;
                      }),
                      !t && (s = c())
                        ? [2, s]
                        : [
                            4,
                            ((p = function () {
                              return Si.acquireLock(
                                'auth0.lock.getTokenSilently',
                                5e3
                              );
                            }),
                            (h = 10),
                            void 0 === h && (h = 3),
                            o(void 0, void 0, void 0, function () {
                              var e;
                              return i(this, function (t) {
                                switch (t.label) {
                                  case 0:
                                    (e = 0), (t.label = 1);
                                  case 1:
                                    return e < h ? [4, p()] : [3, 4];
                                  case 2:
                                    if (t.sent()) return [2, !0];
                                    t.label = 3;
                                  case 3:
                                    return e++, [3, 1];
                                  case 4:
                                    return [2, !1];
                                }
                              });
                            })),
                          ]
                    );
                  case 1:
                    if (!d.sent()) return [3, 10];
                    d.label = 2;
                  case 2:
                    return (
                      d.trys.push([2, , 7, 9]),
                      !t && (s = c())
                        ? [2, s]
                        : this.options.useRefreshTokens
                        ? [4, this._getTokenUsingRefreshToken(a)]
                        : [3, 4]
                    );
                  case 3:
                    return (l = d.sent()), [3, 6];
                  case 4:
                    return [4, this._getTokenFromIFrame(a)];
                  case 5:
                    (l = d.sent()), (d.label = 6);
                  case 6:
                    return (
                      (u = l),
                      this.cache.save(
                        n({ client_id: this.options.client_id }, u)
                      ),
                      this.cookieStorage.save('auth0.is.authenticated', !0, {
                        daysUntilExpire: this.sessionCheckExpiryDays,
                      }),
                      [2, u.access_token]
                    );
                  case 7:
                    return [4, Si.releaseLock('auth0.lock.getTokenSilently')];
                  case 8:
                    return d.sent(), [7];
                  case 9:
                    return [3, 11];
                  case 10:
                    throw new Co();
                  case 11:
                    return [2];
                }
                var p, h;
              });
            })
          );
        }),
        (e.prototype.getTokenWithPopup = function (e, t) {
          return (
            void 0 === e && (e = {}),
            void 0 === t && (t = {}),
            o(this, void 0, void 0, function () {
              return i(this, function (r) {
                switch (r.label) {
                  case 0:
                    return (
                      (e.audience = e.audience || this.options.audience),
                      (e.scope = qo(this.defaultScope, this.scope, e.scope)),
                      (t = n(n({}, Oo), t)),
                      [4, this.loginWithPopup(e, t)]
                    );
                  case 1:
                    return (
                      r.sent(),
                      [
                        2,
                        this.cache.get(
                          new Ho({
                            scope: e.scope,
                            audience: e.audience || 'default',
                            client_id: this.options.client_id,
                          })
                        ).access_token,
                      ]
                    );
                }
              });
            })
          );
        }),
        (e.prototype.isAuthenticated = function () {
          return o(this, void 0, void 0, function () {
            return i(this, function (e) {
              switch (e.label) {
                case 0:
                  return [4, this.getUser()];
                case 1:
                  return [2, !!e.sent()];
              }
            });
          });
        }),
        (e.prototype.buildLogoutUrl = function (e) {
          void 0 === e && (e = {}),
            null !== e.client_id
              ? (e.client_id = e.client_id || this.options.client_id)
              : delete e.client_id;
          var t = e.federated,
            n = r(e, ['federated']),
            o = t ? '&federated' : '';
          return this._url('/v2/logout?' + zo(n)) + o;
        }),
        (e.prototype.logout = function (e) {
          void 0 === e && (e = {});
          var t = e.localOnly,
            n = r(e, ['localOnly']);
          if (t && n.federated)
            throw new Error(
              'It is invalid to set both the `federated` and `localOnly` options to `true`'
            );
          if (
            (this.cache.clear(),
            this.cookieStorage.remove('auth0.is.authenticated'),
            !t)
          ) {
            var o = this.buildLogoutUrl(n);
            window.location.assign(o);
          }
        }),
        (e.prototype._getTokenFromIFrame = function (e) {
          return o(this, void 0, void 0, function () {
            var t, o, a, c, s, u, l, f, d, p, h, y, v, m, g;
            return i(this, function (i) {
              switch (i.label) {
                case 0:
                  return (t = Wo(Ko())), (o = Wo(Ko())), (a = Ko()), [4, Vo(a)];
                case 1:
                  (c = i.sent()),
                    (s = Xo(c)),
                    (u = this._getParams(
                      e,
                      t,
                      o,
                      s,
                      e.redirect_uri ||
                        this.options.redirect_uri ||
                        window.location.origin
                    )),
                    (l = this._authorizeUrl(
                      n(n({}, u), {
                        prompt: 'none',
                        response_mode: 'web_message',
                      })
                    )),
                    (f =
                      e.timeoutInSeconds ||
                      this.options.authorizeTimeoutInSeconds),
                    (i.label = 2);
                case 2:
                  return (
                    i.trys.push([2, 5, , 6]),
                    [
                      4,
                      ((b = l),
                      (w = this.domainUrl),
                      (S = f),
                      void 0 === S && (S = 60),
                      new Promise(function (e, t) {
                        var n = window.document.createElement('iframe');
                        n.setAttribute('width', '0'),
                          n.setAttribute('height', '0'),
                          (n.style.display = 'none');
                        var r,
                          o = function () {
                            window.document.body.contains(n) &&
                              (window.document.body.removeChild(n),
                              window.removeEventListener('message', r, !1));
                          },
                          i = setTimeout(function () {
                            t(new Co()), o();
                          }, 1e3 * S);
                        (r = function (n) {
                          if (
                            n.origin == w &&
                            n.data &&
                            'authorization_response' === n.data.type
                          ) {
                            var a = n.source;
                            a && a.close(),
                              n.data.response.error
                                ? t(Ro.fromPayload(n.data.response))
                                : e(n.data.response),
                              clearTimeout(i),
                              window.removeEventListener('message', r, !1),
                              setTimeout(o, 2e3);
                          }
                        }),
                          window.addEventListener('message', r, !1),
                          window.document.body.appendChild(n),
                          n.setAttribute('src', b);
                      })),
                    ]
                  );
                case 3:
                  if (((d = i.sent()), t !== d.state))
                    throw new Error('Invalid state');
                  return (
                    (p = e.scope),
                    (h = e.audience),
                    e.redirect_uri,
                    e.ignoreCache,
                    e.timeoutInSeconds,
                    (y = r(e, [
                      'scope',
                      'audience',
                      'redirect_uri',
                      'ignoreCache',
                      'timeoutInSeconds',
                    ])),
                    [
                      4,
                      Bo(
                        n(n(n({}, this.customOptions), y), {
                          scope: p,
                          audience: h,
                          baseUrl: this.domainUrl,
                          client_id: this.options.client_id,
                          code_verifier: a,
                          code: d.code,
                          grant_type: 'authorization_code',
                          redirect_uri: u.redirect_uri,
                          auth0Client: this.options.auth0Client,
                        }),
                        this.worker
                      ),
                    ]
                  );
                case 4:
                  return (
                    (v = i.sent()),
                    (m = this._verifyIdToken(v.id_token, o)),
                    [
                      2,
                      n(n({}, v), {
                        decodedToken: m,
                        scope: u.scope,
                        audience: u.audience || 'default',
                      }),
                    ]
                  );
                case 5:
                  throw (
                    ('login_required' === (g = i.sent()).error &&
                      this.logout({ localOnly: !0 }),
                    g)
                  );
                case 6:
                  return [2];
              }
              var b, w, S;
            });
          });
        }),
        (e.prototype._getTokenUsingRefreshToken = function (e) {
          return o(this, void 0, void 0, function () {
            var t, o, a, c, s, u, l, f, d;
            return i(this, function (i) {
              switch (i.label) {
                case 0:
                  return (
                    (e.scope = qo(
                      this.defaultScope,
                      this.options.scope,
                      e.scope
                    )),
                    ((t = this.cache.get(
                      new Ho({
                        scope: e.scope,
                        audience: e.audience || 'default',
                        client_id: this.options.client_id,
                      })
                    )) &&
                      t.refresh_token) ||
                    this.worker
                      ? [3, 2]
                      : [4, this._getTokenFromIFrame(e)]
                  );
                case 1:
                  return [2, i.sent()];
                case 2:
                  (o =
                    e.redirect_uri ||
                    this.options.redirect_uri ||
                    window.location.origin),
                    (c = e.scope),
                    (s = e.audience),
                    e.ignoreCache,
                    e.timeoutInSeconds,
                    (u = r(e, [
                      'scope',
                      'audience',
                      'ignoreCache',
                      'timeoutInSeconds',
                    ])),
                    (l =
                      'number' == typeof e.timeoutInSeconds
                        ? 1e3 * e.timeoutInSeconds
                        : null),
                    (i.label = 3);
                case 3:
                  return (
                    i.trys.push([3, 5, , 8]),
                    [
                      4,
                      Bo(
                        n(
                          n(
                            n(n(n({}, this.customOptions), u), {
                              audience: s,
                              scope: c,
                              baseUrl: this.domainUrl,
                              client_id: this.options.client_id,
                              grant_type: 'refresh_token',
                              refresh_token: t && t.refresh_token,
                              redirect_uri: o,
                            }),
                            l && { timeout: l }
                          ),
                          { auth0Client: this.options.auth0Client }
                        ),
                        this.worker
                      ),
                    ]
                  );
                case 4:
                  return (a = i.sent()), [3, 8];
                case 5:
                  return 'The web worker is missing the refresh token' ===
                    (f = i.sent()).message ||
                    (f.message &&
                      f.message.indexOf('invalid refresh token') > -1)
                    ? [4, this._getTokenFromIFrame(e)]
                    : [3, 7];
                case 6:
                  return [2, i.sent()];
                case 7:
                  throw f;
                case 8:
                  return (
                    (d = this._verifyIdToken(a.id_token)),
                    [
                      2,
                      n(n({}, a), {
                        decodedToken: d,
                        scope: e.scope,
                        audience: e.audience || 'default',
                      }),
                    ]
                  );
              }
            });
          });
        }),
        e
      );
    })(),
    Oi = function () {};

  /**
   * The initial auth state.
   */
  var initialAuthState = {
    isAuthenticated: false,
    isLoading: true,
  };

  /**
   * @ignore
   */
  var stub = function () {
    throw new Error('You forgot to wrap your component in <Auth0Provider>.');
  };
  /**
   * @ignore
   */
  var initialContext = __assign(__assign({}, initialAuthState), {
    buildAuthorizeUrl: stub,
    buildLogoutUrl: stub,
    getAccessTokenSilently: stub,
    getAccessTokenWithPopup: stub,
    getIdTokenClaims: stub,
    loginWithRedirect: stub,
    loginWithPopup: stub,
    logout: stub,
    handleRedirectCallback: stub,
  });
  /**
   * The Auth0 Context
   */
  var Auth0Context = React.createContext(initialContext);

  /**
   * An OAuth2 error will come from the authorization server and will have at least an `error` property which will
   * be the error code. And possibly an `error_description` property
   *
   * See: https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.2.6
   */
  var OAuthError = /** @class */ (function (_super) {
    __extends(OAuthError, _super);
    function OAuthError(error, error_description) {
      var _this = _super.call(this, error_description || error) || this;
      _this.error = error;
      _this.error_description = error_description;
      return _this;
    }
    return OAuthError;
  })(Error);

  var CODE_RE = /[?&]code=[^&]+/;
  var STATE_RE = /[?&]state=[^&]+/;
  var ERROR_RE = /[?&]error=[^&]+/;
  var hasAuthParams = function (searchParams) {
    if (searchParams === void 0) {
      searchParams = window.location.search;
    }
    return (
      (CODE_RE.test(searchParams) || ERROR_RE.test(searchParams)) &&
      STATE_RE.test(searchParams)
    );
  };
  var normalizeErrorFn = function (fallbackMessage) {
    return function (error) {
      if ('error' in error) {
        return new OAuthError(error.error, error.error_description);
      }
      if (error instanceof Error) {
        return error;
      }
      return new Error(fallbackMessage);
    };
  };
  var loginError = normalizeErrorFn('Login failed');
  var tokenError = normalizeErrorFn('Get access token failed');

  /**
   * Handles how that state changes in the `useAuth0` hook.
   */
  var reducer = function (state, action) {
    var _a, _b;
    switch (action.type) {
      case 'LOGIN_POPUP_STARTED':
        return __assign(__assign({}, state), { isLoading: true });
      case 'LOGIN_POPUP_COMPLETE':
      case 'INITIALISED':
        return __assign(__assign({}, state), {
          isAuthenticated: !!action.user,
          user: action.user,
          isLoading: false,
          error: undefined,
        });
      case 'HANDLE_REDIRECT_COMPLETE':
      case 'GET_ACCESS_TOKEN_COMPLETE':
        if (
          ((_a = state.user) === null || _a === void 0
            ? void 0
            : _a.updated_at) ===
          ((_b = action.user) === null || _b === void 0
            ? void 0
            : _b.updated_at)
        ) {
          return state;
        }
        return __assign(__assign({}, state), {
          isAuthenticated: !!action.user,
          user: action.user,
        });
      case 'LOGOUT':
        return __assign(__assign({}, state), {
          isAuthenticated: false,
          user: undefined,
        });
      case 'ERROR':
        return __assign(__assign({}, state), {
          isLoading: false,
          error: action.error,
        });
    }
  };

  /**
   * @ignore
   */
  var toAuth0ClientOptions = function (opts) {
    var clientId = opts.clientId,
      redirectUri = opts.redirectUri,
      maxAge = opts.maxAge,
      validOpts = __rest(opts, ['clientId', 'redirectUri', 'maxAge']);
    return __assign(__assign({}, validOpts), {
      client_id: clientId,
      redirect_uri: redirectUri,
      max_age: maxAge,
      auth0Client: {
        name: 'auth0-react',
        version: '1.5.0',
      },
    });
  };
  /**
   * @ignore
   */
  var toAuth0LoginRedirectOptions = function (opts) {
    if (!opts) {
      return;
    }
    var redirectUri = opts.redirectUri,
      validOpts = __rest(opts, ['redirectUri']);
    return __assign(__assign({}, validOpts), { redirect_uri: redirectUri });
  };
  /**
   * @ignore
   */
  var defaultOnRedirectCallback = function (appState) {
    window.history.replaceState(
      {},
      document.title,
      (appState === null || appState === void 0 ? void 0 : appState.returnTo) ||
        window.location.pathname
    );
  };
  /**
   * ```jsx
   * <Auth0Provider
   *   domain={domain}
   *   clientId={clientId}
   *   redirectUri={window.location.origin}>
   *   <MyApp />
   * </Auth0Provider>
   * ```
   *
   * Provides the Auth0Context to its child components.
   */
  var Auth0Provider = function (opts) {
    var children = opts.children,
      skipRedirectCallback = opts.skipRedirectCallback,
      _a = opts.onRedirectCallback,
      onRedirectCallback = _a === void 0 ? defaultOnRedirectCallback : _a,
      clientOpts = __rest(opts, [
        'children',
        'skipRedirectCallback',
        'onRedirectCallback',
      ]);
    var client = React.useState(function () {
      return new Ti(toAuth0ClientOptions(clientOpts));
    })[0];
    var _b = React.useReducer(reducer, initialAuthState),
      state = _b[0],
      dispatch = _b[1];
    React.useEffect(
      function () {
        (function () {
          return __awaiter(void 0, void 0, void 0, function () {
            var appState, user, error_1;
            return __generator(this, function (_a) {
              switch (_a.label) {
                case 0:
                  _a.trys.push([0, 6, , 7]);
                  if (!(hasAuthParams() && !skipRedirectCallback))
                    return [3 /*break*/, 2];
                  return [4 /*yield*/, client.handleRedirectCallback()];
                case 1:
                  appState = _a.sent().appState;
                  onRedirectCallback(appState);
                  return [3 /*break*/, 4];
                case 2:
                  return [4 /*yield*/, client.checkSession()];
                case 3:
                  _a.sent();
                  _a.label = 4;
                case 4:
                  return [4 /*yield*/, client.getUser()];
                case 5:
                  user = _a.sent();
                  dispatch({ type: 'INITIALISED', user: user });
                  return [3 /*break*/, 7];
                case 6:
                  error_1 = _a.sent();
                  dispatch({ type: 'ERROR', error: loginError(error_1) });
                  return [3 /*break*/, 7];
                case 7:
                  return [2 /*return*/];
              }
            });
          });
        })();
      },
      [client, onRedirectCallback, skipRedirectCallback]
    );
    var buildAuthorizeUrl = React.useCallback(
      function (opts) {
        return client.buildAuthorizeUrl(toAuth0LoginRedirectOptions(opts));
      },
      [client]
    );
    var buildLogoutUrl = React.useCallback(
      function (opts) {
        return client.buildLogoutUrl(opts);
      },
      [client]
    );
    var loginWithRedirect = React.useCallback(
      function (opts) {
        return client.loginWithRedirect(toAuth0LoginRedirectOptions(opts));
      },
      [client]
    );
    var loginWithPopup = React.useCallback(
      function (options, config) {
        return __awaiter(void 0, void 0, void 0, function () {
          var error_2, user;
          return __generator(this, function (_a) {
            switch (_a.label) {
              case 0:
                dispatch({ type: 'LOGIN_POPUP_STARTED' });
                _a.label = 1;
              case 1:
                _a.trys.push([1, 3, , 4]);
                return [4 /*yield*/, client.loginWithPopup(options, config)];
              case 2:
                _a.sent();
                return [3 /*break*/, 4];
              case 3:
                error_2 = _a.sent();
                dispatch({ type: 'ERROR', error: loginError(error_2) });
                return [2 /*return*/];
              case 4:
                return [4 /*yield*/, client.getUser()];
              case 5:
                user = _a.sent();
                dispatch({ type: 'LOGIN_POPUP_COMPLETE', user: user });
                return [2 /*return*/];
            }
          });
        });
      },
      [client]
    );
    var logout = React.useCallback(
      function (opts) {
        if (opts === void 0) {
          opts = {};
        }
        client.logout(opts);
        if (opts.localOnly) {
          dispatch({ type: 'LOGOUT' });
        }
      },
      [client]
    );
    var getAccessTokenSilently = React.useCallback(
      function (opts) {
        return __awaiter(void 0, void 0, void 0, function () {
          var token, error_3, _a, _b;
          return __generator(this, function (_c) {
            switch (_c.label) {
              case 0:
                _c.trys.push([0, 2, 3, 5]);
                return [4 /*yield*/, client.getTokenSilently(opts)];
              case 1:
                token = _c.sent();
                return [3 /*break*/, 5];
              case 2:
                error_3 = _c.sent();
                throw tokenError(error_3);
              case 3:
                _a = dispatch;
                _b = {
                  type: 'GET_ACCESS_TOKEN_COMPLETE',
                };
                return [4 /*yield*/, client.getUser()];
              case 4:
                _a.apply(void 0, [((_b.user = _c.sent()), _b)]);
                return [7 /*endfinally*/];
              case 5:
                return [2 /*return*/, token];
            }
          });
        });
      },
      [client]
    );
    var getAccessTokenWithPopup = React.useCallback(
      function (opts, config) {
        return __awaiter(void 0, void 0, void 0, function () {
          var token, error_4, _a, _b;
          return __generator(this, function (_c) {
            switch (_c.label) {
              case 0:
                _c.trys.push([0, 2, 3, 5]);
                return [4 /*yield*/, client.getTokenWithPopup(opts, config)];
              case 1:
                token = _c.sent();
                return [3 /*break*/, 5];
              case 2:
                error_4 = _c.sent();
                throw tokenError(error_4);
              case 3:
                _a = dispatch;
                _b = {
                  type: 'GET_ACCESS_TOKEN_COMPLETE',
                };
                return [4 /*yield*/, client.getUser()];
              case 4:
                _a.apply(void 0, [((_b.user = _c.sent()), _b)]);
                return [7 /*endfinally*/];
              case 5:
                return [2 /*return*/, token];
            }
          });
        });
      },
      [client]
    );
    var getIdTokenClaims = React.useCallback(
      function (opts) {
        return client.getIdTokenClaims(opts);
      },
      [client]
    );
    var handleRedirectCallback = React.useCallback(
      function (url) {
        return __awaiter(void 0, void 0, void 0, function () {
          var error_5, _a, _b;
          return __generator(this, function (_c) {
            switch (_c.label) {
              case 0:
                _c.trys.push([0, 2, 3, 5]);
                return [4 /*yield*/, client.handleRedirectCallback(url)];
              case 1:
                return [2 /*return*/, _c.sent()];
              case 2:
                error_5 = _c.sent();
                throw tokenError(error_5);
              case 3:
                _a = dispatch;
                _b = {
                  type: 'HANDLE_REDIRECT_COMPLETE',
                };
                return [4 /*yield*/, client.getUser()];
              case 4:
                _a.apply(void 0, [((_b.user = _c.sent()), _b)]);
                return [7 /*endfinally*/];
              case 5:
                return [2 /*return*/];
            }
          });
        });
      },
      [client]
    );
    return React__default.createElement(
      Auth0Context.Provider,
      {
        value: __assign(__assign({}, state), {
          buildAuthorizeUrl: buildAuthorizeUrl,
          buildLogoutUrl: buildLogoutUrl,
          getAccessTokenSilently: getAccessTokenSilently,
          getAccessTokenWithPopup: getAccessTokenWithPopup,
          getIdTokenClaims: getIdTokenClaims,
          loginWithRedirect: loginWithRedirect,
          loginWithPopup: loginWithPopup,
          logout: logout,
          handleRedirectCallback: handleRedirectCallback,
        }),
      },
      children
    );
  };

  /**
   * ```js
   * const {
   *   // Auth state:
   *   error,
   *   isAuthenticated,
   *   isLoading,
   *   user,
   *   // Auth methods:
   *   getAccessTokenSilently,
   *   getAccessTokenWithPopup,
   *   getIdTokenClaims,
   *   loginWithRedirect,
   *   loginWithPopup,
   *   logout,
   * } = useAuth0<TUser>();
   * ```
   *
   * Use the `useAuth0` hook in your components to access the auth state and methods.
   *
   * TUser is an optional type param to provide a type to the `user` field.
   */
  var useAuth0 = function () {
    return React.useContext(Auth0Context);
  };

  /**
   * ```jsx
   * class MyComponent extends Component {
   *   render() {
   *     // Access the auth context from the `auth0` prop
   *     const { user } = this.props.auth0;
   *     return <div>Hello {user.name}!</div>
   *   }
   * }
   * // Wrap your class component in withAuth0
   * export default withAuth0(MyComponent);
   * ```
   *
   * Wrap your class components in this Higher Order Component to give them access to the Auth0Context
   */
  var withAuth0 = function (Component) {
    return function (props) {
      return React__default.createElement(
        Auth0Context.Consumer,
        null,
        function (auth) {
          return React__default.createElement(
            Component,
            __assign({ auth0: auth }, props)
          );
        }
      );
    };
  };

  /**
   * @ignore
   */
  var defaultOnRedirecting = function () {
    return React__default.createElement(React__default.Fragment, null);
  };
  /**
   * @ignore
   */
  var defaultReturnTo = function () {
    return '' + window.location.pathname + window.location.search;
  };
  /**
   * ```js
   * const MyProtectedComponent = withAuthenticationRequired(MyComponent);
   * ```
   *
   * When you wrap your components in this Higher Order Component and an anonymous user visits your component
   * they will be redirected to the login page and returned to the page they we're redirected from after login.
   */
  var withAuthenticationRequired = function (Component, options) {
    if (options === void 0) {
      options = {};
    }
    return function WithAuthenticationRequired(props) {
      var _this = this;
      var _a = useAuth0(),
        user = _a.user,
        isAuthenticated = _a.isAuthenticated,
        isLoading = _a.isLoading,
        loginWithRedirect = _a.loginWithRedirect;
      var _b = options.returnTo,
        returnTo = _b === void 0 ? defaultReturnTo : _b,
        _c = options.onRedirecting,
        onRedirecting = _c === void 0 ? defaultOnRedirecting : _c,
        _d = options.loginOptions,
        loginOptions = _d === void 0 ? {} : _d,
        _e = options.claimCheck,
        claimCheck =
          _e === void 0
            ? function () {
                return true;
              }
            : _e;
      /**
       * The route is authenticated if the user has valid auth and there are no
       * JWT claim mismatches.
       */
      var routeIsAuthenticated = isAuthenticated && claimCheck(user);
      React.useEffect(
        function () {
          if (isLoading || routeIsAuthenticated) {
            return;
          }
          var opts = __assign(__assign({}, loginOptions), {
            appState: __assign(__assign({}, loginOptions.appState), {
              returnTo: typeof returnTo === 'function' ? returnTo() : returnTo,
            }),
          });
          (function () {
            return __awaiter(_this, void 0, void 0, function () {
              return __generator(this, function (_a) {
                switch (_a.label) {
                  case 0:
                    return [4 /*yield*/, loginWithRedirect(opts)];
                  case 1:
                    _a.sent();
                    return [2 /*return*/];
                }
              });
            });
          })();
        },
        [
          isLoading,
          routeIsAuthenticated,
          loginWithRedirect,
          loginOptions,
          returnTo,
        ]
      );
      return routeIsAuthenticated
        ? React__default.createElement(Component, __assign({}, props))
        : onRedirecting();
    };
  };

  exports.Auth0Context = Auth0Context;
  exports.Auth0Provider = Auth0Provider;
  exports.OAuthError = OAuthError;
  exports.User = Oi;
  exports.useAuth0 = useAuth0;
  exports.withAuth0 = withAuth0;
  exports.withAuthenticationRequired = withAuthenticationRequired;

  Object.defineProperty(exports, '__esModule', { value: true });
});
//# sourceMappingURL=auth0-react.js.map
