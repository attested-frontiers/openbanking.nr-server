import { Sequelize, DataTypes } from 'sequelize';
import path from 'path';
import { fileURLToPath } from 'url';

// Get directory path in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create SQLite database
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, 'db.sqlite'),
  logging: false,
});

// Define Commitment model
const Commitment = sequelize.define('Commitment', {
  commitment: {
    type: DataTypes.STRING,
    primaryKey: true,
    unique: true,
  },
  sortCode: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  // sortCode: {
  //   type: DataTypes.STRING,
  //   allowNull: false
  // },
  // salt: {
  //   type: DataTypes.STRING,
  //   allowNull: false
  // }
});

const Pubkey = sequelize.define('Pubkey', {
  // TODO: Is kid unique enough for this to be a valid storage key?
  kid: {
    type: DataTypes.STRING,
    primaryKey: true,
    unique: true,
  },
});

// Sync model with database
sequelize.sync();

// ===== Commitment =====

export async function createCommitment(commitmentData) {
  try {
    return await Commitment.create(commitmentData);
  } catch (error) {
    console.error('Error creating commitment:', error);
    throw error;
  }
}

export async function purgeCommitments() {
  try {
    await Commitment.destroy({
      where: {}, // No conditions, deletes all records
      truncate: true, // Optionally, use truncate to reset the auto-increment counter
    });
  } catch (error) {
    console.error('Error deleting all commitments:', error);
    throw error;
  }
}

export async function getCommitmentByHash(commitment) {
  try {
    return await Commitment.findByPk(hash);
  } catch (error) {
    console.error('Error retrieving commitment:', error);
    throw error;
  }
}

export async function getAllCommitments() {
  try {
    return await Commitment.findAll();
  } catch (error) {
    console.error('Error retrieving all commitments:', error);
    throw error;
  }
}

// ===== Pubkey =====

export async function getAllPubkeys() {
  try {
    const pubkeys = await Pubkey.findAll();
    return pubkeys.map((pubkey) => ({ kid: pubkey.dataValues.kid }));
  } catch (error) {
    console.error('Error retrieving all pubkeys:', error);
    throw error;
  }
}

export async function purgePubkeys() {
  try {
    await Pubkey.destroy({
      where: {}, // No conditions, deletes all records
      truncate: true, // Optionally, use truncate to reset the auto-increment counter
    });
  } catch (error) {
    console.error('Error deleting all commitments:', error);
    throw error;
  }
}

export async function updatePubkeys(newPubkeys, revokedPubkeys) {
  try {
    if (revokedPubkeys.length) {
      await Pubkey.destroy({
        where: {
          kid: revokedPubkeys,
        },
      });
    }
    if (newPubkeys.length) {
      await Pubkey.bulkCreate(newPubkeys);
    }
  } catch (error) {
    console.error('Error creating pubkey:', error);
    throw error;
  }
}
