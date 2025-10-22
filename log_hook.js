// log_hook.js
// Frida hook: перехват Log.* и System.out.println, детект и redaction чувствительных данных,
// запись POC в stdout frida и попытка append в /data/local/tmp/frida_sensitive_poc.jsonl

Java.perform(function () {
    var Log = null;
    try { Log = Java.use("android.util.Log"); } catch (e) { /* не Java-процесс */ }

    var PrintStream = null;
    try { PrintStream = Java.use("java.io.PrintStream"); } catch (e) { /* может отсутствовать */ }

    var Pattern = null;
    try { Pattern = Java.use("java.util.regex.Pattern"); } catch (e) { Pattern = null; }

    // регекс на чувствительные слова/ключи (расширяй при необходимости)
    var sensitivePattern = "(?i)(password|passwd|pwd|pin|otp|token|bearer|authorization|sessionid|set-cookie|secret|jwt|access_token|refresh_token|cardnumber|card|cvv|ssn|email|phone|apikey)";
    var pat = null;
    try {
        if (Pattern) pat = Pattern.compile(sensitivePattern);
    } catch (e) { pat = null; }

    // helper: проверка, содержит ли строка чувствительное
    function isSensitive(s) {
        if (!s) return false;
        try {
            if (pat) {
                return pat.matcher(s).find();
            } else {
                // fallback простая проверка
                var low = s.toLowerCase();
                var keys = ["password","token","bearer","authorization","sessionid","secret","jwt","access_token","refresh_token","card","cvv","email","phone","apikey","otp","pin"];
                for (var i=0;i<keys.length;i++){
                    if (low.indexOf(keys[i]) !== -1) return true;
                }
                return false;
            }
        } catch (e) {
            return false;
        }
    }

    // helper: redaction — простые правила замены
    function redact(s) {
        if (!s) return s;
        try {
            // маскируем Bearer токены
            s = s.replace(/(bearer\s+)(\S+)/ig, "$1[REDACTED]");
            // access/refresh/token key=value или JSON "token":"..."
            s = s.replace(/(access_token\s*[:=]\s*\"?\S+\"?)/ig, "access_token=[REDACTED]");
            s = s.replace(/(refresh_token\s*[:=]\s*\"?\S+\"?)/ig, "refresh_token=[REDACTED]");
            s = s.replace(/("token"\s*:\s*")([^"]+)(")/ig, "$1[REDACTED]$3");
            s = s.replace(/(token\s*[:=]\s*\S+)/ig, "token=[REDACTED]");
            // пароли
            s = s.replace(/(password\s*[:=]\s*\"?\S+\"?)/ig, "password=[REDACTED]");
            // номера карт ~ последовательности цифр 13-19
            s = s.replace(/(\b\d[ -]*\d[ -]*\d[ -]*\d[ -]*\d[ -]*\d[ -]*\d[ -]*\d[ -]*\d[ -]*\d[ -]*\d[ -]*\d[ -]*\d{1,}\b)/g, function(m){
                // очень простая маска: оставляем только последние 4 цифры
                var digits = m.replace(/[^0-9]/g,"");
                if (digits.length >= 13 && digits.length <= 19) {
                    return "[CARD_REDACTED_END_"+digits.slice(-4)+"]";
                }
                return m;
            });
        } catch (e) {}
        return s;
    }

    // helper: попытка записать JSON-line в /data/local/tmp/frida_sensitive_poc.jsonl
    function appendPocToDevice(jsonstr) {
        try {
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            // true = append
            var fos = FileOutputStream.$new("/data/local/tmp/frida_sensitive_poc.jsonl", true);
            // build byte array
            var bytes = Java.array('byte', (jsonstr + '\n').split('').map(function(c){ return c.charCodeAt(0); }));
            fos.write(bytes);
            fos.close();
            return true;
        } catch (e) {
            // запись может быть запрещена на не-root устройстве
            return false;
        }
    }

    // helper: формируем и логируем POC (в stdout frida и пытаемся в файл)
    function reportPoc(original, redacted) {
        try {
            var obj = { time: (new Date()).toISOString(), original: original, redacted: redacted };
            var json = JSON.stringify(obj);
            // вывод в frida stdout (видно в консоли)
            console.warn("[FRIDA_POC] " + json);
            // попытка записать на устройство
            appendPocToDevice(json);
        } catch (e) {}
    }

    // Hook Log methods (v,d,i,w,e,wtf) с сигнатурой (String tag, String msg)
    try {
        if (Log) {
            ['v','d','i','w','e','wtf'].forEach(function(level){
                try {
                    var overloads = Log[level].overloads;
                    overloads.forEach(function(ov){
                        ov.implementation = function(tag, msg) {
                            try {
                                var s = msg ? msg.toString() : null;
                                if (isSensitive(s)) {
                                    var red = redact(s);
                                    reportPoc(s, red);
                                    return ov.call(this, tag, red);
                                }
                                return ov.call(this, tag, s);
                            } catch (inner) {
                                // если что-то ломается — вернуть оригинал
                                return ov.call(this, tag, msg);
                            }
                        };
                    });
                } catch(e){}
            });
        }
    } catch (e) {}

    // Hook System.out/System.err -> java.io.PrintStream.println
    try {
        if (PrintStream) {
            PrintStream.println.overloads.forEach(function(ov){
                try {
                    ov.implementation = function(obj) {
                        try {
                            var s = obj ? obj.toString() : null;
                            if (isSensitive(s)) {
                                var red = redact(s);
                                reportPoc(s, red);
                                return ov.call(this, red);
                            }
                            return ov.call(this, s);
                        } catch (inner) {
                            return ov.call(this, obj);
                        }
                    };
                } catch(e){}
            });
        }
    } catch (e) {}

    console.log("[FRIDA] log hooks installed");
});
