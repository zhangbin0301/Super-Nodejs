const FILE_PATH = process.env.FILE_PATH || '/tmp';
const intervalInseconds = process.env.TIME || 100;
const CFIP = process.env.CFIP || 'ip.sb';
const CFPORT = process.env.CFPORT || '443';
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const OPENSERVER = (process.env.OPENSERVER || 'true') === 'true';
const KEEPALIVE = (process.env.KEEPALIVE || 'false') === 'true';
const MY_DOMAIN = process.env.MY_DOMAIN || '';
const V_DOMAIN = process.env.V_DOMAIN || '';
const V_AUTH = process.env.V_AUTH || '';

const VLPATH = process.env.VLPATH || '';
const XHPPATH = process.env.XHPPATH || '';

const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;
const V_PORT = process.env.V_PORT || 8080;

const UUID = process.env.UUID || '';
const NVERSION = process.env.NVERSION || 'V0';
const NSERVER = process.env.NSERVER || '';
const NPORT = process.env.NPORT || '443';
const NKEY = process.env.NKEY || '';
const SNAME = process.env.SNAME || '';
const SURL = process.env.SURL || '';

const axios = require("axios");
const { pipeline } = require('stream/promises');
const os = require('os');
const fs = require("fs");
const path = require("path");
const http = require('http');
const https = require('https');
const exec = require("child_process").exec;

function createFolder(folderPath) {
    try {
        fs.statSync(folderPath);
        // console.log(`${folderPath} already exists`);
    } catch (err) {
        if (err.code === 'ENOENT') {
            fs.mkdirSync(folderPath);
            // console.log(`${folderPath} is created`);
        } else {
            // console.log(`Error handling ${FILE_PATH}: ${error.message}`);
        }
    }
}

function httpserver() {
    const server = http.createServer((req, res) => {
        if (req.url === '/') {
            res.writeHead(200);
            res.end('hello world');
        } else if (req.url === `/${UUID}`) {
            const subFilePath = FILE_PATH + '/log.txt';
            fs.readFile(subFilePath, 'utf8', (error, data) => {
                if (error) {
                    res.writeHead(500);
                    res.end('Error reading file');
                } else {
                    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
                    res.end(data);
                }
            });
        } else {
            res.writeHead(404);
            res.end('Not found');
        }
    });
    server.listen(PORT, () => {
        console.log(`server is running on port : ${PORT}`);
    });
}

function execPromise(command, options = {}) {
    return new Promise((resolve, reject) => {
        const child = exec(command, options, (error, stdout, stderr) => {
            if (error) {
                const err = new Error(`Command failed: ${error.message}`);
                err.code = error.code;
                err.stderr = stderr.trim();
                reject(err);
            } else {
                resolve(stdout.trim());
            }
        });
    });
}

async function detectProcess(processName) {
    const methods = [
        { cmd: `pidof "${processName}"`, name: 'pidof' },
        { cmd: `pgrep -x "${processName}"`, name: 'pgrep' },
        { cmd: `ps -eo pid,comm | awk -v name="${processName}" '$2 == name {print $1}'`, name: 'ps+awk' }
    ];

    for (const method of methods) {
        try {
            const stdout = await execPromise(method.cmd);
            if (stdout) {
                return stdout.replace(/\n/g, ' ').trim();
            }
        } catch (error) {
            if (error.code !== 127 && error.code !== 1) {
                console.debug(`[detectProcess] ${method.name} error:`, error.message);
            }
        }
    }
    return '';
}

async function killProcess(process_name) {
    console.log(`Attempting to kill process: ${process_name}`);
    try {
        const pids = await detectProcess(process_name);
        if (!pids) {
            console.warn(`Process '${process_name}' not found`);
            return { success: true, message: 'Process not found' };
        }

        await execPromise(`kill -9 ${pids}`);
        const msg = `Killed process (PIDs: ${pids})`;
        console.log(msg);
        return { success: true, message: msg };

    } catch (error) {
        const msg = `Kill failed: ${error.message}`;
        console.error(msg);
        return { success: false, message: msg };
    }
}

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

async function myconfig() {
    const configpath = path.join(FILE_PATH, 'xconf');
    const vlpath = '/' + VLPATH;
    const xhppath = '/' + XHPPATH;
    function generateConfig() {
        const inbound = {
            "log": {
                "access": "/dev/null",
                "error": "/dev/null",
                "loglevel": "none"
            },
            "dns": {
                "servers": [
                    "https+local://8.8.8.8/dns-query"
                ]
            }
        };
        fs.writeFileSync(path.join(configpath, 'inbound.json'), JSON.stringify(inbound, null, 2));

        if ((VLPATH) && (!XHPPATH)) {
            const inbound_v = {
                "inbounds": [
                    {
                        "port": V_PORT,
                        "listen": "::",
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {
                                    "id": UUID,
                                    "level": 0
                                }
                            ],
                            "decryption": "none"
                        },
                        "streamSettings": {
                            "network": "ws",
                            "security": "none",
                            "wsSettings": {
                                "path": vlpath
                            }
                        },
                        "sniffing": {
                            "enabled": true,
                            "destOverride": [
                                "http",
                                "tls",
                                "quic"
                            ],
                            "metadataOnly": false
                        }
                    }
                ]
            };
            fs.writeFileSync(path.join(configpath, 'inbound_v.json'), JSON.stringify(inbound_v, null, 2));
        } else if ((XHPPATH) && (!VLPATH)) {
            const inbound_v = {
                "inbounds": [
                    {
                        "port": V_PORT,
                        "listen": "::",
                        "protocol": "vless",
                        "settings": {
                            "clients": [
                                {
                                    "id": UUID
                                }
                            ],
                            "decryption": "none"
                        },
                        "streamSettings": {
                            "network": "xhttp",
                            "security": "none",
                            "xhttpSettings": {
                                "mode": "packet-up",
                                "path": xhppath
                            }
                        },
                        "sniffing": {
                            "enabled": true,
                            "destOverride": [
                                "http",
                                "tls",
                                "quic"
                            ],
                            "metadataOnly": false
                        }
                    }
                ]
            };
            fs.writeFileSync(path.join(configpath, 'inbound_v.json'), JSON.stringify(inbound_v, null, 2));
        }

        const outbound = {
            "outbounds": [
                {
                    "tag": "direct",
                    "protocol": "freedom"
                },
                {
                    "tag": "block",
                    "protocol": "blackhole"
                }
            ]
        };
        fs.writeFileSync(path.join(configpath, 'outbound.json'), JSON.stringify(outbound, null, 2));
    }

    generateConfig();
}

function getSystemArchitecture() {
    const arch = os.arch();
    if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
        return 'arm';
    } else {
        return 'amd';
    }
}

function getFilesForArchitecture(architecture) {
    const FILE_URLS = {
        bot: {
            arm: "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64",
            amd: "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
        },
        web: {
            arm: "https://github.com/mytcgd/myfiles/releases/download/main/xray_arm",
            amd: "https://github.com/mytcgd/myfiles/releases/download/main/xray"
        },
        npm: {
            V0: {
                arm: "https://github.com/kahunama/myfile/releases/download/main/nezha-agent_arm",
                amd: "https://github.com/kahunama/myfile/releases/download/main/nezha-agent"
            },
            V1: {
                arm: "https://github.com/mytcgd/myfiles/releases/download/main/nezha-agentv1_arm",
                amd: "https://github.com/mytcgd/myfiles/releases/download/main/nezha-agentv1"
            }
        }
    };
    let baseFiles = [
        { fileName: generateRandomString(5), originalName: "web", fileUrl: FILE_URLS.web[architecture] }
    ];

    if (OPENSERVER) {
        const botFile = {
            fileName: generateRandomString(5),
            originalName: "bot",
            fileUrl: FILE_URLS.bot[architecture]
        };
        baseFiles.push(botFile);
    }

    if (NSERVER && NPORT && NKEY && NVERSION) {
        const npmFile = {
            fileName: generateRandomString(5),
            originalName: "npm",
            fileUrl: FILE_URLS.npm[NVERSION][architecture]
        };
        baseFiles.push(npmFile);
    }

    return baseFiles;
}

async function download_function(fileName, originalName, fileUrl) {
    const filePath = path.join(FILE_PATH, fileName);
    let downloadSuccess = false;

    try {
        const response = await axios({
            method: 'get',
            url: fileUrl,
            responseType: 'stream',
        });
        await pipeline(response.data, fs.createWriteStream(filePath));
        // console.log(`Download ${originalName} (renamed to ${fileName}) successfully`);
        downloadSuccess = true;
    } catch (err) {
        // console.log(`Download ${originalName} (renamed to ${fileName}) failed: ${err.message}`);
    }

    return { fileName, originalName, filePath, success: downloadSuccess };
}

let fileMapping = {};
async function downloadFiles() {
    try {
        const architecture = getSystemArchitecture();
        if (!architecture) {
            console.log(`Can't determine system architecture.`);
            return fileMapping;
        }

        const filesToDownload = getFilesForArchitecture(architecture);
        if (filesToDownload.length === 0) {
            console.log(`Can't find a file for the current architecture`);
            return fileMapping;
        }

        const downloadPromises = filesToDownload.map(fileInfo =>
        download_function(fileInfo.fileName, fileInfo.originalName, fileInfo.fileUrl)
        );
        const downloadedFilesInfo = await Promise.all(downloadPromises);

        downloadedFilesInfo.forEach(info => {
            if (info.success) {
                try {
                    fs.chmodSync(info.filePath, 0o755);
                    // console.log(`Empowerment success for ${info.fileName}: 755`);
                    fileMapping[info.originalName] = info.fileName;
                } catch (err) {
                    // console.warn(`Empowerment failed for ${info.fileName}: ${err.message}`);
                }
            }
        });

        return fileMapping;
    } catch (err) {
        console.error('Error downloading files:', err);
        return fileMapping;
    }
}

function argoType() {
    if (!V_AUTH || !V_DOMAIN) {
        // console.log("V_DOMAIN or V_AUTH variable is empty, use quick tunnels");
        return;
    }

    if (V_AUTH.includes('TunnelSecret')) {
        fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), V_AUTH);
        const tunnelYaml = `
        tunnel: ${V_AUTH.split('"')[11]}
        credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
        protocol: http2

        ingress:
        - hostname: ${V_DOMAIN}
        service: http://localhost:${V_PORT}
        originRequest:
        noTLSVerify: true
        - service: http_status:404
        `;
        fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
    } else {
        // console.log("V_AUTH mismatch TunnelSecret,use token connect to tunnel");
    }
}

let args;
function get_cloud_flare_args() {
    if (V_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
        args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${V_AUTH}`;
    } else if (V_AUTH.match(/TunnelSecret/)) {
        args = `tunnel --edge-ip-version auto --config ${FILE_PATH}/tunnel.yml run`;
    } else {
        args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${V_PORT}`;
    }
    return args
}

let NTLS;
function nezconfig() {
    const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
    if (NVERSION === 'V0') {
        if (tlsPorts.includes(NPORT)) {
            NTLS = '--tls';
        } else {
            NTLS = '';
        }
        return NTLS
    } else if (NVERSION === 'V1') {
        if (tlsPorts.includes(NPORT)) {
            NTLS = 'true';
        } else {
            NTLS = 'false';
        }
        const nezv1configPath = path.join(FILE_PATH, '/config.yml');
        const v1configData = `client_secret: ${NKEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 4
server: ${NSERVER}:${NPORT}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: ${NTLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
        try {
            fs.writeFileSync(nezv1configPath, v1configData);
            // console.log('config.yml file created and written successfully.');
        } catch (err) {
            // console.error('Error creating or writing config.yml file:', err);
        }
    }
}

async function runbot() {
    const botFilePath = path.join(FILE_PATH, fileMapping['bot']);
    try {
        fs.statSync(botFilePath);
        try {
            await execPromise(`nohup ${FILE_PATH}/${fileMapping['bot']} ${args} >/dev/null 2>&1 &`);
        } catch (error) {
            console.error(`${fileMapping['bot']} running error: ${error}`);
        }
    } catch (statError) {
        if (statError.code === 'ENOENT') {
            console.log('bot file not found, skip running');
        } else {
            // console.error(`Error checking bot file: ${statError.message}`);
        }
    }
}

async function runweb() {
    const webFilePath = path.join(FILE_PATH, fileMapping['web']);
    try {
        fs.statSync(webFilePath);
        try {
            await execPromise(`nohup ${FILE_PATH}/${fileMapping['web']} run -confdir ${FILE_PATH}/xconf >/dev/null 2>&1 &`);
        } catch (error) {
            console.error(`${fileMapping['web']} running error: ${error}`);
        }
    } catch (statError) {
        if (statError.code === 'ENOENT') {
            console.log('web file not found, skip running');
        } else {
            // console.error(`Error checking web file: ${statError.message}`);
        }
    }
}

async function runnpm() {
    const npmFilePath = path.join(FILE_PATH, fileMapping['npm']);
    try {
        fs.statSync(npmFilePath);
        try {
            if (NVERSION === 'V0') {
                await execPromise(`nohup ${FILE_PATH}/${fileMapping['npm']} -s ${NSERVER}:${NPORT} -p ${NKEY} ${NTLS} --report-delay=4 --skip-conn --skip-procs --disable-auto-update >/dev/null 2>&1 &`);
            } else if (NVERSION === 'V1') {
                await execPromise(`nohup ${FILE_PATH}/${fileMapping['npm']} -c ${FILE_PATH}/config.yml >/dev/null 2>&1 &`);
            }
        } catch (error) {
            console.error(`${fileMapping['npm']} running error: ${error}`);
        }
    } catch (statError) {
        if (statError.code === 'ENOENT') {
            console.log('npm file not found, skip running');
        } else {
            // console.error(`Error checking web file: ${statError.message}`);
        }
    }
}

async function runapp() {
    if (OPENSERVER) {
        argoType();
        get_cloud_flare_args();
        await runbot();
        await delay(5000);
        // console.log(`${fileMapping['bot']} is running`);
    } else {
        console.log('bot variable is not allowed, skip running');
    }

    await runweb();
    await delay(1000);
    // console.log(`${fileMapping['web']} is running`);

    if (NVERSION && NSERVER && NPORT && NKEY) {
        nezconfig();
        await runnpm();
        await delay(1000);
        // console.log(`${fileMapping['npm']} is running`);
    } else {
        console.log('npm variable is empty, skip running');
    }
}

async function keep_alive() {
    const webPids = await detectProcess(`${fileMapping['web']}`);
    if (webPids) {
        // console.log("${fileMapping['web']} is already running. PIDs:", webPids);
    } else {
        // console.log(`${fileMapping['web']} runs again !`);
        await runweb();
    }

    await delay(5000);

    if (OPENSERVER) {
        const botPids = await detectProcess(`${fileMapping['bot']}`);
        if (botPids) {
            // console.log("${fileMapping['bot']} is already running. PIDs:", botPids);
        } else {
            // console.log(`${fileMapping['bot']} runs again !`);
            await runbot();
        }
    }

    await delay(5000);

    if (NVERSION && NSERVER && NPORT && NKEY) {
        const npmPids = await detectProcess(`${fileMapping['npm']}`);
        if (npmPids) {
            // console.log("${fileMapping['npm']} is already running. PIDs:", npmPids);
        } else {
            // console.log(`${fileMapping['npm']} runs again !`);
            await runnpm();
        }
    }
}

function getArgoDomainFromLog() {
    const bootfilePath = path.join(FILE_PATH, 'boot.log');
    try {
        const stats = fs.statSync(bootfilePath);
        if (stats.size === 0) {
            return null;
        }

        const fileContent = fs.readFileSync(bootfilePath, 'utf-8');
        const regex = /info.*https:\/\/(.*trycloudflare\.com)/g;
        let match;
        let lastMatch = null;

        while ((match = regex.exec(fileContent)) !== null) {
            lastMatch = match[1];
        }
        return lastMatch;
    } catch (error) {
        if (error.code === 'ENOENT') return null;
        console.error('Error reading boot.log:', error);
        return null;
    }
}

function buildurl(argoDomain) {
    let Node_DATA = '';
    if (VLPATH) {
        Node_DATA = `vless://${UUID}@${CFIP}:${CFPORT}?host=${argoDomain}&path=%2F${VLPATH}%3Fed%3D2560&type=ws&encryption=none&security=tls&sni=${argoDomain}#${ISP}-${SNAME}`;
    } else if (XHPPATH) {
        Node_DATA = `vless://${UUID}@${CFIP}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&type=xhttp&host=${argoDomain}&path=%2F${XHPPATH}%3Fed%3D2560&mode=packet-up#${ISP}-${SNAME}`;
    }
    return Node_DATA;
}

let argoDomain, UPLOAD_DATA;
async function extractDomains() {
    let currentArgoDomain = null;
    if (OPENSERVER === true) {
        if (V_AUTH && V_DOMAIN) {
            currentArgoDomain = V_DOMAIN;
            // console.log('Using configured V_DOMAIN:', currentArgoDomain);
        } else {
            await delay(3000);
            currentArgoDomain = getArgoDomainFromLog();
            if (!currentArgoDomain) {
                try {
                    console.log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
                    const bootfilePath = path.join(FILE_PATH, 'boot.log');
                    try {
                        fs.statSync(bootfilePath);
                        try {
                            fs.unlinkSync(bootfilePath);
                            await delay(500);
                        } catch (error) {
                            console.error(`Error deleting boot.log: ${error}`);
                        }
                    } catch (error) {
                        if (error.code !== 'ENOENT') {
                            console.error(`Error checking boot.log: ${error}`);
                        }
                    }
                    const botprocess = `${fileMapping['bot']}`;
                    await killProcess(botprocess);
                    await delay(1000);
                    await runbot();
                    console.log(`${fileMapping['bot']} is running`);
                    await delay(10000);
                    currentArgoDomain = getArgoDomainFromLog();
                    if (!currentArgoDomain) {
                        console.error('Failed to obtain ArgoDomain even after restarting bot.');
                    }
                } catch (error) {
                    console.error('Error in bot process management:', error);
                    return;
                }
            } else {
                // console.log('ArgoDomain extracted from boot.log:', currentArgoDomain);
            }
        }
    }

    if (MY_DOMAIN) {
        currentArgoDomain = MY_DOMAIN;
        // console.log('Overriding ArgoDomain with MY_DOMAIN:', currentArgoDomain);
    }

    argoDomain = currentArgoDomain;
    if (!argoDomain) {
        console.error('No domain could be determined. Cannot construct UPLOAD_DATA');
        UPLOAD_DATA = '';
        return;
    }

    UPLOAD_DATA = buildurl(argoDomain);
    // console.log('UPLOAD_DATA:', UPLOAD_DATA);
}

async function getCloudflareMeta() {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'speed.cloudflare.com',
            path: '/meta',
            method: 'GET',
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                const parsedData = JSON.parse(data);
                resolve(parsedData);
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.end();
    });
}

let ISP;
async function getipandisp() {
    let data = await getCloudflareMeta();
    let fields1 = data.country;
    let fields2 = data.asOrganization;
    //ISP = (fields1 + '-' + fields2).replace(/ /g, '_');
    ISP = await (await fetch("https://ipconfig.netlib.re")).text();
    // console.log(ISP);
}

function generateLinks() {
    if (UPLOAD_DATA) {
        const filePath = path.join(FILE_PATH, 'log.txt');
        fs.writeFileSync(filePath, Buffer.from(UPLOAD_DATA).toString('base64'));
        // console.log(Buffer.from(UPLOAD_DATA).toString('base64'));
    }
}

async function uploadSubscription(SNAME, UPLOAD_DATA, SURL) {
    const payload = JSON.stringify({ URL_NAME: SNAME, URL: UPLOAD_DATA });

    const postData = Buffer.from(payload, 'utf8');
    const contentLength = postData.length;
    const parsedUrl = new URL(SURL);
    const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': contentLength
        }
    };

    try {
        const responseBody = await new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                if (res.statusCode < 200 || res.statusCode >= 300) {
                    return reject(new Error(`HTTP error! status: ${res.statusCode}, response: ${res.statusMessage}`));
                }
                let responseBody = '';
                res.on('data', (chunk) => responseBody += chunk);
                res.on('end', () => resolve(responseBody));
            });
            req.on('error', (error) => reject(error));
            req.write(postData);
            req.end();
        });
        // console.log('Upload successful:', responseBody);
        return responseBody;
    } catch (error) {
        console.error(`Upload failed:`, error.message);
    }
}

function cleanfiles() {
    setTimeout(() => {
        let filesToDelete;
        if (KEEPALIVE) {
            filesToDelete = [];
        } else {
            filesToDelete = [
                `${FILE_PATH}/${fileMapping['bot']}`,
                `${FILE_PATH}/${fileMapping['web']}`,
                `${FILE_PATH}/${fileMapping['npm']}`,
                `${FILE_PATH}/xconf`,
                `${FILE_PATH}/config.yml`
            ];
        }

        filesToDelete.forEach(filePath => {
            try {
                const stats = fs.statSync(filePath);

                if (stats.isDirectory()) {
                    fs.rmSync(filePath, { recursive: true });
                } else {
                    fs.unlinkSync(filePath);
                }
                // console.log(`${filePath} deleted`);
            } catch (error) {
                if (error.code !== 'ENOENT') {
                    // console.error(`Failed to delete ${filePath}: ${error}`);
                }
            }
        });

        console.clear()
        console.log('App is running');
    }, 60000);
}

let previousargoDomain = '';
async function subupload() {
    if (previousargoDomain && argoDomain === previousargoDomain) {
        // console.log('domain name has not been updated, no need to upload');
    } else {
        const response = await uploadSubscription(SNAME, UPLOAD_DATA, SURL);
        generateLinks();
        previousargoDomain = argoDomain;
    }
    await delay(50000);
    await extractDomains();
}

// main
async function main() {
    createFolder(FILE_PATH);
    createFolder(path.join(FILE_PATH, 'xconf'));
    await downloadFiles();
    await delay(5000);
    await getipandisp();
    await myconfig();
    await runapp();
    await extractDomains();
    generateLinks();
    httpserver();
    cleanfiles();
    if (SURL) {
        const response = await uploadSubscription(SNAME, UPLOAD_DATA, SURL);
        if (KEEPALIVE && OPENSERVER && !V_AUTH && !V_DOMAIN) {
            previousargoDomain = argoDomain;
            setInterval(subupload, intervalInseconds * 1000);
            // setInterval(subupload, 100000);  //100s
        }
    }
    if (KEEPALIVE) {
        await keep_alive();
        setInterval(keep_alive, intervalInseconds * 1000);
    }
}
main();
