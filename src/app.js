const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const routes = require('./api/routes/v1');
const demoRoutes = require('./api/routes/demo.routes');
const tracking = require('./api/middlewares/tracking.middleware');

const app = express();

app.use(bodyParser.json());
app.use(tracking);

app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'ktb-codemender-banking-demo', project: 'lenin-ai-playground' });
});

app.use('/api/v1/demo', demoRoutes);
app.use('/api/v1', routes);
app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

module.exports = app;