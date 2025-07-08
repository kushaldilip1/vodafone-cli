// The core application

const { Command } = require('commander');
const axios = require('axios');
const cheerio = require('cheerio');
const inquirer = require('inquirer'); // Changed from destructuring to import the whole object
const keytar = require('keytar');
const chalk = require('chalk');

const program = new Command();

const ROUTER_IP = 'http://192.168.1.1';
const SERVICE_NAME = 'vodafone-router-cli';
const USERNAME_KEY = 'router_username';
const PASSWORD_KEY = 'router_password';

// A global variable to store session cookies after a successful login
let currentSessionCookies = [];

/**
 * This is going to act as a Helper Function which is to extract CSRF token or other hidden authentication tokens
 * from an HTML page. This details are specific to the router in case.
 * @param {string}          html:the content of the page (HTML)
 * @returns {string|null}   The extracted token if not null, otherwise null if not found
 */

function extractAuthToken(html) {
    const $ = cheerio.load(html);

    // Got this token referential from the html page of the vodafone routre login page
    const csrfToken = $('meta[name="CSRFtoken"]').attr('content');
    if (csrfToken) {
        console.log(chalk.default.gray(`    (Debug) Extracted CSRF Token: ${csrfToken.substring(0, 10)}...`));
        return csrfToken;
    }

    //Warning message when token is not found or null
    console.warn(chalk.default.yellow(`    (Warning) Login might fail due to not finding common CSRF token from the original website.`));
    return null;
}

/**
 * This is to attempt to login into the router and return the sesion cookies
 * This function is router specific (for other users wishing to use this implementation)
 * @param {string} username: The router username
 * @param {string} password: The router password
 * @returns {Promise<string[] | null}   An array of session cookies if the login is successful
 */

async function performLogin(password) {
    console.log(chalk.default.blue(`Attempting to login to ${ROUTER_IP}...`));
    try {
        //Get the login page to potentially fetch cookies and CSRF token
        const loginPageResponse = await axios.get(`${ROUTER_IP}/login.lp`, { withCredentials: true });

        const initialCookies = loginPageResponse.headers['set-cookie'] || [];
        console.log(chalk.default.gray(`    (Debug) Initial cookies from login page: ${String(initialCookies.join(';')).substring(0, 50)}...`));

        const csrfToken = extractAuthToken(loginPageResponse.data);
        if (!csrfToken) {
            console.warn(chalk.default.yellow(' (Warning) Login not possible due to no CSRF token found.'));
        }


        /**
         * Preparing the POST request for login
         */

        const loginPostUrl = `${ROUTER_IP}/authenticate`; // Correct endpoint for SRP authentication
        const formData = new URLSearchParams();
        //formData.append('username', username); // Username is typically fixed to 'admin' for Vodafone routers
        formData.append('password', password);
        if (csrfToken) {
            formData.append('csrf_token', csrfToken);
        }

        const loginResponse = await axios.post(loginPostUrl, formData.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': initialCookies.join(';')
            },

            maxRedirects: 0,  //this is to prevent axios from following automatic redirects
            validateStatus: (status) => status >= 200 && status < 300. //This is to accepts the 200 and 300 status
        });

        const sessionCookies = loginResponse.headers['set-cookie'] || [];
        const redirectLocation = loginResponse.headers.location;




        if (sessionCookies.length > 0 && loginResponse.status === 302) {
            console.log(chalk.default.green('Login successful! Session established.'));
            return sessionCookies;
        } else {
            console.error(chalk.default.red('Login failed: Unexpected response or no session established.'));
            console.error(chalk.default.red('Response Status:', loginResponse.status));
            console.error(chalk.default.red('Redirect Location:', redirectLocation)); // Added for debugging
            console.error(chalk.default.red('Response Data:', loginResponse.data.substring(0, 200))); // For debugging
            return null;
        }
    }

    catch (error) {
        console.error(chalk.default.red('Error during login'));
        if (error.response) {
            console.error(chalk.default.red(`   Status: ${error.response.status}`));
            console.error(chalk.default.red(`   Data: ${error.response.data.substring(0, 200)}`));
            console.error(chalk.default.red(`   Headers: ${JSON.stringify(error.response.headers)}`));
        }
        else if (error.request) {
            console.error(chalk.default.red(`   No response received. Check your network connectivity and confirm your IP Address.`));
        }
        else {
            console.error(chalk.default.red(`   Message: ${error.message}`));
        }
        return null;
    }
}


/**
 * The next step is to fetch and parse the list of connected devices
 * @param {string[]}    sessionCookies: An Array of session cookies obtained after successful login
 * @returns {Promise<Array<{name: string, ip: string}>>}    An array of devices listed.
 */
async function getConnectedDevices(sessionCookies) {
    console.log(chalk.default.blue('Fetching connected devices list...'));
    if (!sessionCookies || sessionCookies.length === 0) {
        console.error(chalk.default.red('Please login first, no session cookies accessible'));
        return [];
    }

    try {
        // ---  JSON API identified where the devices are listed    ---
        const devicesApiUrl = `${ROUTER_IP}/modal/overview.lp?deviceslist=true`;

        console.log(chalk.default.blue(`Attempting to fetch the devices from: ${devicesApiUrl}`));

        const response = await axios.get(devicesApiUrl, {
            headers: {
                'Cookie': sessionCookies.join(";")  //  This is to send the session cookies
            },
            withCredentials: true   //  Ensure the cookies are sent and received
        });

        const responseData = response.data;

        //  Checking if the response is HTML based, essentially meaning the session is expired or authentication failed
        if (typeof responseData === 'string' && responseData.includes('<html')) {
            console.error(chalk.default.red('Error: Received HTML repsonse instead of JSON, session cookies are either expired or invalid'));
            return [];
        }

        const connectedDevices = [];


        //  Process 2.4GHz wifi devices
        if (responseData.wifiList24 && Array.isArray(responseData.wifiList24)) {
            responseData.wifiList24.forEach(device => {
                connectedDevices.push({
                    name: device.FriendlyName || device.HostName || "N/A",
                    ip_address: device.IPAddress || "N/A",
                    mac_address: device.MACAddress || "N/A",
                    connection_type: device.radio ? `${String(device.radio).replace(/[\(\)]/g, '')} Wi-Fi` : "N/A",
                    state: device.State === "1" ? "Active" : "Inactive",
                    manufacturer: device.Manufacturer || "N/A",
                    model: device.Model || "N/A",
                    os_family: device["X_VF_ADTI.OSFamily"] || "N/A",
                    speed_mbps: device.Speed || "N/A"
                });
            });
        }

        //  Process 5GHz wifi devices
        if (responseData.wifiList5 && Array.isArray(responseData.wifiList5)) {
            responseData.wifiList5.forEach(device => {
                connectedDevices.push({
                    name: device.FriendlyName || device.HostName || "N/A",
                    ip_address: device.IPAddress || "N/A",
                    mac_address: device.MACAddress || "N/A",
                    connection_type: device.radio ? `${String(device.radio).replace(/[\(\)]/g, '')} Wi-Fi` : "N/A",
                    state: device.State === "1" ? "Active" : "Inactive",
                    manufacturer: device.Manufacturer || "N/A",
                    model: device.Model || "N/A",
                    os_family: device["X_VF_ADTI.OSFamily"] || "N/A",
                    speed_mbps: device.Speed || "N/A"
                });
            });
        }

        //  Process devices connected via Ethernet Network
        if (responseData.ethlist && Array.isArray(responseData.ethlist)) {
            responseData.ethlist.forEach(device => {
                connectedDevices.push({
                    name: device.FriendlyName || device.HostName || "N/A",
                    ip_address: device.IPAddress || "N/A",
                    mac_address: device.MACAddress || "N/A",
                    connection_type: "Ethernet",
                    state: device.State === "1" ? "Active" : "Inactive",
                    manufacturer: device.Manufacturer || "N/A",
                    model: device.Model || "N/A",
                    os_family: device["X_VF_ADTI.OSFamily"] || "N/A",
                    speed_mbps: device.Speed || "N/A"
                });
            });
        }

        //  Process devices connected via USB Connection
        if (responseData.USBDeviceDetails && Array.isArray(responseData.USBDeviceDetails)) {
            responseData.USBDeviceDetails.forEach(device => {
                connectedDevices.push({
                    name: device.FriendlyName || device.HostName || "N/A",
                    ip_address: device.IPAddress || "N/A",
                    mac_address: device.MACAddress || "N/A",
                    connection_type: "USB",
                    state: device.State === "1" ? "Active" : "Inactive",
                    manufacturer: device.Manufacturer || "N/A",
                    model: device.Model || "N/A",
                    os_family: device["X_VF_ADTI.OSFamily"] || "N/A",
                    speed_mbps: device.Speed || "N/A"
                });
            });
        }


        return connectedDevices;
    }
    catch (error) {
        console.error(chalk.default.red('Error fetching connected devices:'));
        if (error.response) {
            console.error(chalk.default.red(`   Status: ${error.response.status}`));
            console.error(chalk.default.red(`   Repsonse Data (first 500 chars): ${JSON.stringify(error.response.data || '').substring(0, 500)}...`));
        }
        else if (error.request) {
            console.error(chalk.default.red(`   No response received for devices API. Please check your network our your router port.`));
        }
        else {
            console.error(chalk.default.red(`   Message: ${error.message}`));
        }
        return [];
    }
}

//  ----    CLI Commands Setup  ----
program
    .name('vodafone')
    .description('A CLI tool to interact with your vodafone router');

program
    .command('login')
    .description('Logs into the vodafone router and securely saves the credentials')
    .action(async () => {
        

        const answers = await inquirer.default.prompt([ // Corrected to inquirer.default.prompt
            {
                type: 'password',
                name: 'password',
                message: 'Enter your router password',
                mask: '*'
            },
            {
                type: 'confirm',
                name: 'save',
                message: 'Save password securely for future use?',
                default: true
            }
        ]);

        const { password, save } = answers;

        if (save) {
            try {
                await keytar.setPassword(SERVICE_NAME, PASSWORD_KEY, password);
                console.log(chalk.default.green('Credentials saved securely'));
            } catch (error) { // Added error parameter for clarity
                console.error(chalk.default.red('Failed to save the login credentials'), error.message);
                console.error(chalk.default.yellow('Session can be continued, however, you will need to re-enter the credentials next time'));
            }
        } else {
            console.log(chalk.default.yellow('Credentials will not be saved'));
        }

        const session = await performLogin(password);
        if (session) {
            currentSessionCookies = session;
            console.log(chalk.default.green('Login test successful, you can now access the list command'));
        } else {
            console.error(chalk.default.red('Login test failed, please check your password or router configurations'));
        }
    });

program
    .command('list')
    .description('Lists all the connected devices (names and IP) from the route page for the router')
    .action(async () => {
        

        // Original code commented out below for reference:
         let password = await keytar.getPassword(SERVICE_NAME, PASSWORD_KEY);
         if (!password) {
             console.warn(chalk.default.yellow('No saved credentials. Prompting for login details...'));
             const answers = await inquirer.default.prompt([ // Corrected to inquirer.default.prompt
                 {
                     type: 'password',
                     name: 'password',
                     message: 'Enter your password',
                     mask: '*'
                 }
             ]);
             password = answers.password;
             console.log(chalk.default.blue('Attempting login with provided credentials (not saved)'));
         } else {
             console.log(chalk.default.blue('Using stored credentials to login'));
         }

         currentSessionCookies = await performLogin(password);

         if (!currentSessionCookies || currentSessionCookies.length === 0) {
             console.error(chalk.default.red('Failed to establish a connection. Unable to list devices'));
             return;
         }

         const devices = await getConnectedDevices(currentSessionCookies);

         if (devices.length > 0) {
             console.log(chalk.default.blue('\n---   Connected Devices     ---'));
             devices.forEach((device, index) => {
                 console.log(chalk.default.cyan(`    ${index + 1}. Name: ${chalk.default.green(device.name)}`));
                 console.log(chalk.default.cyan(`    IP Address: ${chalk.default.magenta(device.ip_address)}`));
                 console.log(chalk.default.cyan(`    MAC Address: ${chalk.default.white(device.mac_address)}`));
                 console.log(chalk.default.cyan(`    Connection Type: ${chalk.default.yellow(device.connection_type)}`));
                 console.log(chalk.default.cyan(`    Status: ${device.state === '1' ? chalk.default.green('Active') : chalk.default.red('Inactive')}`));
                 if (device.manufacturer !== 'N/A') console.log(chalk.default.cyan(`    Manufacturer: ${chalk.default.gray(device.manufacturer)}`));
                 if (device.model !== 'N/A') console.log(chalk.default.cyan(`    Model: ${chalk.default.gray(device.model)}`));
                 if (device.os_family !== 'N/A') console.log(chalk.default.cyan(`    OS Family: ${chalk.default.gray(device.os_family)}`));
                 if (device.speed_mbps !== 'N/A') console.log(chalk.default.cyan(`   Speed MBps: ${chalk.default.gray(device.speed_mbps)} MBps`));
                 console.log('');
             });
             console.log(chalk.default.gray('------------------------------/n'));
         } else {
             console.log(chalk.default.yellow('No connected devices located or the device list is not accessible'));
         }
    });

program.parse(process.argv);