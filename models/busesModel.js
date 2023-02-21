const mongoose = require('mongoose');

const busSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  number: {
    type: String,
    required: true
  },
  capacity: {
    type: Number,
    required: true
  },
  from: {
    type: String,
    required: true
  },
  to: {
    type: String,
    reuired: true
  },
  journeyDate: {
    type: String,
    required: true
  },
  departure: {
    type: String,
    required: true
  },
  arrival: {
    type: String,
    required: true
  },
  type: {
    type: String,
    default: 'AC'
  },
  fare: {
    type: Number,
    required: true
  },
  seatsBooked: {
    type: Array,
    default: []
  },
  status: {
    type: String,
    default: 'Yet To Start'
  }
});

module.exports = mongoose.model('buses', busSchema);