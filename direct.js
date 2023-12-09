// document.onkeydown =
//   document.onkeyup =
//   document.onkeypress =
//     function (event) {
//       var e = event || window.event || arguments.callee.caller.arguments[0];
//       if (e && e.keyCode == 123) {
//         mAlert();
//         e.returnValue = false;
//         return false;
//       }
//     };
// function mAlert() {
// //   alert("感谢使用管理平台，禁止对控制台进行操作！");
// }
// // setInterval(function () {
// //   debugger;
// // }, 100);
function base64_encode(input) {
  var chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  var data = String(input),
    o1,
    o2,
    o3,
    bits,
    i = 0,
    acc = "";

  while (i < data.length) {
    o1 = data.charCodeAt(i++);
    o2 = data.charCodeAt(i++);
    o3 = data.charCodeAt(i++);

    if (o1 > 255 || o2 > 255 || o3 > 255) {
      console.log(
        "'base64_encode' failed: The string to be encoded contains characters outside of the Latin1 range."
      );
    }

    bits = (o1 << 16) | (o2 << 8) | o3;
    acc +=
      chars.charAt((bits >> 18) & 0x3f) +
      chars.charAt((bits >> 12) & 0x3f) +
      chars.charAt((bits >> 6) & 0x3f) +
      chars.charAt(bits & 0x3f);
  }

  switch (data.length % 3) {
    case 0:
      return acc;
    case 1:
      return acc.slice(0, -2) + "==";
    case 2:
      return acc.slice(0, -1) + "=";
  }
}

function base64_decode(input) {
  var chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  var str = String(input).replace(/[=]+$/, "");
  if (str.length % 4 === 1) {
    console.log(
      "'base64_decode' failed: The string to be decoded is not correctly encoded."
    );
  }
  for (
    var bc = 0, bs, buffer, idx = 0, output = "";
    (buffer = str.charAt(idx++));

  ) {
    buffer = chars.indexOf(buffer);
    ~buffer && ((bs = bc % 4 ? bs * 64 + buffer : buffer), bc++ % 4)
      ? (output += String.fromCharCode(255 & (bs >> ((-2 * bc) & 6))))
      : 0;
  }
  return output;
}

function authcode(str, operation, key, expiry) {
  var operation = operation ? operation : "DECODE";
  var key = key ? key : "";
  var expiry = expiry ? expiry : 0;

  var ckey_length = 4;
  key = md5(key);

  // 密匙a会参与加解密
  var keya = md5(key.substr(0, 16));
  // 密匙b会用来做数据完整性验证
  var keyb = md5(key.substr(16, 16));
  // 密匙c用于变化生成的密文
  // IE下不支持substr第一个参数为负数的情况
  if (ckey_length) {
    if (operation == "DECODE") {
      var keyc = str.substr(0, ckey_length);
    } else {
      var md5_time = md5(microtime());
      var start = md5_time.length - ckey_length;
      var keyc = md5_time.substr(start, ckey_length);
    }
  } else {
    var keyc = "";
  }
  // 参与运算的密匙
  var cryptkey = keya + md5(keya + keyc);

  var strbuf;

  if (operation == "DECODE") {
    str = str.substr(ckey_length);
    strbuf = base64_decode(str);
    //string = b.toString();
  } else {
    expiry = expiry ? expiry + time() : 0;
    tmpstr = expiry.toString();
    if (tmpstr.length >= 10)
      str = tmpstr.substr(0, 10) + md5(str + keyb).substr(0, 16) + str;
    else {
      var count = 10 - tmpstr.length;
      for (var i = 0; i < count; i++) {
        tmpstr = "0" + tmpstr;
      }
      str = tmpstr + md5(str + keyb).substr(0, 16) + str;
    }
    strbuf = str;
  }

  var box = new Array(256);
  for (var i = 0; i < 256; i++) {
    box[i] = i;
  }

  var rndkey = new Array();
  // 产生密匙簿
  for (var i = 0; i < 256; i++) {
    rndkey[i] = cryptkey.charCodeAt(i % cryptkey.length);
  }

  // 用固定的算法，打乱密匙簿，增加随机性，好像很复杂，实际上对并不会增加密文的强度
  for (var j = (i = 0); i < 256; i++) {
    j = (j + box[i] + rndkey[i]) % 256;
    tmp = box[i];
    box[i] = box[j];
    box[j] = tmp;
  }

  // 核心加解密部分
  var s = "";
  //IE下不支持直接通过下标访问字符串的字符，需要先转换为数组
  strbuf = strbuf.split("");
  for (var a = (j = i = 0); i < strbuf.length; i++) {
    a = (a + 1) % 256;
    j = (j + box[a]) % 256;
    tmp = box[a];
    box[a] = box[j];
    box[j] = tmp;
    // 从密匙簿得出密匙进行异或，再转成字符
    s += chr(ord(strbuf[i]) ^ box[(box[a] + box[j]) % 256]);
  }

  if (operation == "DECODE") {
    if (
      (s.substr(0, 10) == 0 || s.substr(0, 10) - time() > 0) &&
      s.substr(10, 16) == md5(s.substr(26) + keyb).substr(0, 16)
    ) {
      s = s.substr(26);
    } else {
      s = "";
    }
  } else {
    s = base64_encode(s);
    var regex = new RegExp("=", "g");
    s = s.replace(regex, "");
    s = keyc + s;
  }
  return s;
}

function time() {
  var unixtime_ms = new Date().getTime();
  return parseInt(unixtime_ms / 1000);
}

function microtime(get_as_float) {
  var unixtime_ms = new Date().getTime();
  var sec = parseInt(unixtime_ms / 1000);
  return get_as_float
    ? unixtime_ms / 1000
    : (unixtime_ms - sec * 1000) / 1000 + " " + sec;
}

function chr(s) {
  return String.fromCharCode(s);
}

function ord(s) {
  return s.charCodeAt();
}
document.oncontextmenu = function () {
  return false;
};
//获取#之后的内容，进行authcode解密
//取消转义的hash
var hash = window.location.hash;
var x = authcode(window.location.hash.substr(1), "DECODE", "xy3githubfh");
$(function () {
  let u = window.document.location.href.toString().split("?");
  if (typeof u[1] == "string") {
    u = u[1].split("&");
  } else {
    u = "";
  }

  iframe(x + u);
});

function iframe(src) {
  $("div").html(
    '<iframe src="' +
      src +
      '" width="100%" frameborder=0 allow="camera;microphone" height="' +
      ($(window).height()-3) +
      "px" +
      '" style="border: 0"></iframe>'
  );
  $(window).resize();
}
//检测窗口大小变化就resize
window.addEventListener("resize", function () {
  $("iframe").height($($(window).height() - 3));
});
