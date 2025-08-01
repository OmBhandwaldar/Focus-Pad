import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import router from './routes/index';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use('/api', router);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
