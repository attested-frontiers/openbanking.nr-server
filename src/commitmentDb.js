import { Sequelize, DataTypes } from 'sequelize';
import path from 'path';
import { fileURLToPath } from 'url';

// Get directory path in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Create SQLite database
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, 'commitments.sqlite'),
  logging: false
});

// Define Commitment model
const Commitment = sequelize.define('Commitment', {
  hash: {
    type: DataTypes.STRING,
    primaryKey: true,
    unique: true
  },
  accountNumber: {
    type: DataTypes.STRING,
    allowNull: false
  },
  sortCode: {
    type: DataTypes.STRING,
    allowNull: false
  },
  amount: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: false
  },
  salt: {
    type: DataTypes.STRING,
    allowNull: false
  }
});

// Sync model with database
sequelize.sync();

export async function createCommitment(commitmentData) {
  try {
    return await Commitment.create(commitmentData);
  } catch (error) {
    console.error('Error creating commitment:', error);
    throw error;
  }
}

export async function getCommitmentByHash(hash) {
  try {
    return await Commitment.findByPk(hash);
  } catch (error) {
    console.error('Error retrieving commitment:', error);
    throw error;
  }
}

// Export for use in main server file
export default Commitment;