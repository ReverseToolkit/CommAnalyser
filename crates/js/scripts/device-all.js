(function () {
    var out = [];
    function check(name, fn) {
        try {
            var v = fn();
            if (v === true || v === undefined) {
                out.push(name + ':ok');
            } else {
                out.push(name + ':' + v);
            }
        } catch (e) {
            out.push(name + ':ERR ' + e);
        }
    }

    check('memory.queryProtection', function () {
        var p = Memory.alloc(32);
        var prot = Memory.queryProtection(p);
        return prot.indexOf('r') >= 0 ? true : prot;
    });
    check('memory.allocUtf16String', function () {
        var p = Memory.allocUtf16String('ab');
        return p.readU16() === 0x61;
    });
    check('memory.findPointers', function () {
        var buf = Memory.alloc(32);
        var needle = ptr('0x1122334455667788');
        buf.writePointer(needle);
        var hits = Memory.findPointers(buf, 16, [needle]);
        return hits.length >= 1 && hits[0].compare(buf) === 0;
    });
    check('memory.scan', function () {
        var buf = Memory.alloc(32);
        buf.writePointer(ptr('0x1122334455667788'));
        var n = 0;
        Memory.scan(buf, 16, '88 77 66 55', {
            onMatch: function () { n++; },
            onComplete: function () {}
        });
        var sync = Memory.scanSync(buf, 16, '88 77 66 55');
        return n >= 1 && sync.length >= 1;
    });
    check('memory.copyDupProtect', function () {
        var src = Memory.allocUtf8String('xyz');
        var d = Memory.dup(src, 4);
        Memory.copy(d, src, 4);
        Memory.protect(d, 16, 'rw-');
        return d.readCString() === 'xyz';
    });

    check('process.mainModule', function () {
        return Process.mainModule && Process.mainModule.base && Process.mainModule.name.length > 0;
    });
    check('process.findModuleByAddress', function () {
        var m = Process.findModuleByAddress(Process.mainModule.base);
        return m && m.contains
            ? m.name.length > 0
            : !!(m && m.name);
    });
    check('process.enumerateThreads', function () {
        var threads = Process.enumerateThreads();
        return threads.length > 0 && threads.some(function (t) { return t.id > 0; });
    });
    check('process.enumerateRanges', function () {
        return Process.enumerateRanges('r-x').length > 0;
    });
    check('process.findRangeByAddress', function () {
        var r = Process.findRangeByAddress(Process.mainModule.base);
        return r && r.size > 0;
    });
    check('process.dirs', function () {
        return typeof Process.getCurrentDir() === 'string' &&
            typeof Process.getHomeDir() === 'string' &&
            typeof Process.getTmpDir() === 'string';
    });
    check('process.isDebuggerAttached', function () {
        return typeof Process.isDebuggerAttached() === 'boolean';
    });

    check('module.exports', function () {
        var malloc = Module.getExportByName('libc.so', 'malloc') ||
            Module.getExportByName(null, 'malloc');
        return malloc && !malloc.isNull();
    });
    check('module.sections', function () {
        var libc = Process.findModuleByName('libc.so');
        return libc && libc.enumerateSections().length > 0;
    });
    check('module.dependencies', function () {
        var libc = Process.findModuleByName('libc.so');
        return libc && libc.enumerateDependencies() instanceof Array;
    });
    check('module.ranges', function () {
        var libc = Process.findModuleByName('libc.so');
        return libc && libc.enumerateRanges().length > 0;
    });
    check('moduleMap', function () {
        var map = new ModuleMap();
        return map.has(Process.mainModule.base);
    });

    check('thread.backtrace', function () {
        var frames = Thread.backtrace();
        return frames instanceof Array;
    });
    check('thread.hw', function () {
        var p = Memory.alloc(8);
        Thread.setHardwareBreakpoint(0, p);
        Thread.unsetHardwareBreakpoint(0);
        Thread.setHardwareWatchpoint(0, p, 8);
        Thread.unsetHardwareWatchpoint(0);
        return true;
    });
    check('nativePointer.pac', function () {
        var p = ptr('0x1234');
        return p.toJSON() === p.toString() &&
            p.toMatchPattern().split(' ').length === 8 &&
            p.blend(1).compare(p) !== 0;
    });

    check('nativeFunction.malloc', function () {
        var malloc = new NativeFunction(Module.getExportByName(null, 'malloc'), 'pointer', ['int']);
        var free = new NativeFunction(Module.getExportByName(null, 'free'), 'void', ['pointer']);
        var block = malloc(32);
        block.writeU32(0x41);
        var v = block.readU32();
        free(block);
        return v === 65;
    });

    check('interceptor.attach', function () {
        var getpid = Module.getExportByName('libc.so', 'getpid') ||
            Module.getExportByName(null, 'getpid');
        var hits = 0;
        var listener = Interceptor.attach(getpid, {
            onEnter: function () { hits++; }
        });
        var fn = new NativeFunction(getpid, 'int', []);
        var pid = fn();
        listener.detach();
        return hits >= 1 && pid > 0;
    });
    check('interceptor.replace', function () {
        var page = Memory.alloc(Process.pageSize);
        Memory.protect(page, Process.pageSize, 'rwx');
        page.writeU32(0xd503201f);
        var replacement = Memory.alloc(16);
        Interceptor.replace(page, replacement);
        var after = page.readU32() >>> 0;
        Interceptor.revert(page);
        var restored = page.readU32() >>> 0;
        return (after === 0x58000050) && (restored === 0xd503201f);
    });

    check('java.available', function () {
        return Java.available === true;
    });
    check('java.useString', function () {
        var ok = false;
        Java.perform(function () {
            var S = Java.use('java.lang.String');
            var s = S.$new('hello');
            ok = s.length() === 5 && S.$className === 'java.lang.String';
        });
        return ok;
    });
    check('java.implementation', function () {
        var result = null;
        Java.perform(function () {
            var SB = Java.use('java.lang.StringBuilder');
            var s = SB.$new('hello');
            var before = s.length();
            SB.length.implementation = function () { return 99; };
            var hooked = s.length();
            SB.length.implementation = null;
            var after = SB.$new('hello').length();
            result = { before: before, hooked: hooked, after: after };
        });
        return result && result.before === 5 && result.hooked === 99 && result.after === 5
            ? true
            : JSON.stringify(result);
    });
    check('java.chooseCast', function () {
        var result = null;
        Java.perform(function () {
            var inst = null;
            Java.choose('android.app.Activity', {
                onMatch: function (obj) { inst = obj; return 'stop'; },
                onComplete: function () {}
            });
            var Act = Java.use('android.app.Activity');
            var c = Java.cast(inst, Act);
            var r = Java.retain(c);
            var arr = Java.array('int', [1, 2, 3]);
            result = c.$isSameObject(r) && arr.$className === '[I';
        });
        return result;
    });

    check('file.roundtrip', function () {
        var path = '/data/user/0/com.android.settings/cache/ca-device-file.txt';
        File.writeAllText(path, 'hello\n');
        if (File.readAllText(path) !== 'hello\n') return 'readAllText';
        var f = new File(path, 'r');
        var line = f.readLine();
        f.close();
        return line.indexOf('hello') >= 0;
    });
    check('debugSymbol', function () {
        var d = DebugSymbol.fromName('malloc');
        if (d.address.isNull()) return 'fromName';
        var a = DebugSymbol.fromAddress(d.address);
        return a.address.compare(d.address) === 0;
    });
    check('arm64Writer', function () {
        var page = Memory.alloc(16);
        var w = new Arm64Writer(page);
        w.putNop();
        w.putBrkImm(1);
        w.flush();
        w.dispose();
        return (page.readU32() >>> 0) === 0xd503201f;
    });
    check('timeout.zero', function () {
        var hit = 0;
        setTimeout(function () { hit = 1; }, 0);
        return true;
    });

    return out.join('\n');
})()
