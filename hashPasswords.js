const bcrypt = require('bcrypt');
(async () => {
    const saltRounds = 10;
    const adminPass = await bcrypt.hash('adminpassword', saltRounds);
    const userPass = await bcrypt.hash('userpassword', saltRounds);
    const sandboxPass = await bcrypt.hash('Fd&5cb4VZ', saltRounds);
    console.log(`Admin: ${adminPass}`);
    console.log(`User: ${userPass}`);
    console.log(`Sandbox: ${sandboxPass}`);
})();