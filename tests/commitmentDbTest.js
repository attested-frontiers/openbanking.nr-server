import { createCommitment, getCommitmentByHash } from '../src/commitmentDb.js';
import crypto from 'crypto';

async function testCommitmentDb() {
  // Generate a sample hash
  const salt = crypto.randomBytes(16).toString('hex');
  const commitmentData = {
    hash: crypto.createHash('sha256')
      .update(`12345678${salt}`)
      .digest('hex'),
    accountNumber: '12345678',
    sortCode: '12-34-56',
    amount: 100.50,
    salt: salt
  };

  try {
    // Create commitment
    const createdCommitment = await createCommitment(commitmentData);
    console.log('Created Commitment:', createdCommitment.toJSON());

    // Retrieve commitment
    const retrievedCommitment = await getCommitmentByHash(commitmentData.hash);
    console.log('Retrieved Commitment:', retrievedCommitment.toJSON());

    // Verify data
    console.log('Test Passed:', 
      retrievedCommitment.hash === commitmentData.hash &&
      retrievedCommitment.accountNumber === commitmentData.accountNumber
    );
  } catch (error) {
    console.error('Test Failed:', error);
  }
}

testCommitmentDb();