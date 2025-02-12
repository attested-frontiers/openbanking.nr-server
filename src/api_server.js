import express from 'express';
import dotenv from 'dotenv';
import { initializePayment } from './paymentService.js';
import { createCommitment, getCommitmentByHash } from './commitmentDb.js';

dotenv.config();

const app = express();
app.use(express.json());

// Simple ping endpoint to check if the server is alive
app.get('/ping', (req, res) => {
    res.json({ message: 'pong' });
});

// Health check endpoint to check if the server is healthy
app.get('/health', async (req, res) => {
    try {
        // Check critical service health (e.g., database, third-party APIs)
        // TODO: add database health tests
        const isDbHealthy = 1;
        if (!isDbHealthy) {
            return res.status(500).json({ status: 'error', message: 'Database is down' });
        }
        res.json({ status: 'ok', message: 'Server is healthy' });
    } catch (error) {
        res.status(500).json({ status: 'error', message: error.message });
    }
});

app.post('/api/initialize-payment', async (req, res) => {
    try {
        const paymentData = req.body;
        const result = await initializePayment(paymentData);
        res.json(result);
    } catch (error) {
        console.error('Payment initiation error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST endpoint to create a commitment
app.post('/commitment', async (req, res) => {
    try {
      const { hash, accountNumber, sortCode, amount, salt } = req.body;
      const commitment = await createCommitment({ 
        hash, 
        accountNumber, 
        sortCode, 
        amount, 
        salt 
      });
      res.status(201).json(commitment);
    } catch (error) {
      res.status(500).json({ 
        error: 'Failed to create commitment', 
        details: error.message 
      });
    }
  });

// GET endpoint to retrieve a commitment by hash
app.get('/commitment/:hash', async (req, res) => {
    try {
      const commitment = await getCommitmentByHash(req.params.hash);
      if (!commitment) {
        return res.status(404).json({ error: 'Commitment not found' });
      }
      res.json(commitment);
    } catch (error) {
      res.status(500).json({ 
        error: 'Failed to retrieve commitment', 
        details: error.message 
      });
    }
  });

  // GET endpoint to retrieve all commitments
app.get('/commitments', async (req, res) => {
    try {
      const commitments = await getAllCommitments();
      res.json(commitments);
    } catch (error) {
      res.status(500).json({ 
        error: 'Failed to retrieve commitments', 
        details: error.message 
      });
    }
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// export for testing purposes
export default app;
