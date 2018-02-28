const chai = require('chai');
const dirtyChai = require('dirty-chai');

chai.use(dirtyChai);

process.on('unhandledRejection', (error) => {
  throw error;
});
