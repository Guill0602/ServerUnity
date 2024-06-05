const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const storage = multer.memoryStorage(); // Store file in memory
const upload = multer({ storage: storage });



// Middleware for parsing JSON and URL-encoded data
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
app.use(cors());
app.use(bodyParser.json());


// Session middleware setup
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false
}));

// MongoDB Connection
mongoose.connect('mongodb+srv://guillsango:gu6FoXUc5xUJe72m@streaming.m5diqrb.mongodb.net/EcommerceApp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('Failed to connect to MongoDB', err);
});

// Define Schema and Model for id_numbers collection
const idNumberSchema = new mongoose.Schema({
    id_number: String
});
const IdNumber = mongoose.model('IdNumber', idNumberSchema);

// Define Schema and Model for user collection
const userSchema = new mongoose.Schema({
    email: { type: String, unique: true },
    password: String,
    id_number: String,
    productList: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
    }]
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    const user = this;
    if (!user.isModified('password')) return next();

    try {
        const hash = await bcrypt.hash(user.password, 10);
        user.password = hash;
        next();
    } catch (error) {
        return next(error);
    }
});

const User = mongoose.model('User', userSchema);

// Define Schema and Model for product collection
const productSchema = new mongoose.Schema({
    productName: String,
    price: Number,
    description: String,
    status: {
        type: String,
        enum: ['New', 'Sports Equipment']
    },
    category: {
        type: String,
        enum: ['Sneaker', 'Books', 'Clothing', 'Bags', 'Technology', 'Sports Equipment', 'Sneakers']
    },
    
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    productImage: {
        data: Buffer,
        contentType: String
    }
});

const Product = mongoose.model('Product', productSchema);

// Registration Endpoint
app.post('/register', async (req, res) => {
    const { email, password, id_number } = req.body;

    try {
        const idNumberExists = await IdNumber.exists({ id_number });

        if (!idNumberExists) {
            return res.status(400).send('Invalid id_number');
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).send('Email is already registered');
        }

        const newUser = new User({ email, password, id_number });
        await newUser.save();

        res.status(200).send('User registered successfully');
    } catch (error) {
        console.error('Error registering user:', error); // More detailed error logging
        res.status(500).send('Error registering user: ' + error.message); // Include error message
    }
});

// Login Endpoint
app.post('/login', async (req, res) => {
    const { identifier, password } = req.body; // identifier can be email or id_number

    try {
        const user = await User.findOne({ $or: [{ email: identifier }, { id_number: identifier }] });

        if (!user) {
            return res.status(400).send('Invalid identifier or password');
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(400).send('Invalid identifier or password');
        }

        // Set user session after successful login
        req.session.userId = user._id;

        res.json({ userId: user._id, message: 'Login successful' }); // Send user ID along with the response
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).send('Error logging in user');
    }
});


app.get('/get-user-profile', async (req, res) => {
    const userId = req.query.userId;

    try {
        const user = await User.findById(userId)
            .select('email id_number productList')
            .populate('productList'); // Populate productList with full product details

        if (!user) {
            return res.status(404).send('User not found');
        }

        res.json({ 
            email: user.email, 
            id_number: user.id_number, 
            productList: user.productList.map(product => ({
                productName: product.productName,
                price: product.price,
                description: product.description,
                status: product.status,
                category: product.category,
                productImage: product.productImage.data.toString('base64') // Send image as base64 string
            }))
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).send('Error fetching user profile');
    }
});


// Get Product Details Endpoint
app.get('/get-product-details', async (req, res) => {
    const productId = req.query.productId;

    try {
        const product = await Product.findById(productId).populate('userId', 'email');

        if (!product) {
            return res.status(404).send('Product not found');
        }

        res.json({
            productName: product.productName,
            price: product.price,
            description: product.description,
            status: product.status,
            category: product.category,
            productImage: product.productImage.data.toString('base64') // Send image as base64 string
        });
    } catch (error) {
        console.error('Error fetching product details:', error);
        res.status(500).send('Error fetching product details');
    }
});


// Define the route for GET /get-all-products
app.get('/get-all-products', async (req, res) => {
    try {
        const products = await Product.find().populate('userId', 'email');

        const formattedProducts = products.map(product => ({
            productName: product.productName,
            price: product.price,
            description: product.description,
            status: product.status,
            category: product.category,
            productImage: product.productImage.data.toString('base64'), // Keep image as is
            userId: product.userId._id,
            userEmail: product.userId.email
        }));

        res.json(formattedProducts);
    } catch (error) {
        console.error('Error fetching all products:', error);
        res.status(500).send('Error fetching all products');
    }
});


// Add Product Endpoint with image upload
app.post('/add-product', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.session.userId;

    try {
        const { productName, price, description, status, category, productImage } = req.body;

        // Check if user exists
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        const imageBuffer = Buffer.from(productImage, 'base64');

        // Debug: Log product details before saving
        console.log('Product Details:');
        console.log('Product Name:', productName);
        console.log('Price:', price);
        console.log('Description:', description);
        console.log('Status:', status);
        console.log('Category:', category);
        console.log('User ID:', userId);
        console.log('User ID:', productImage);

        // Decode base64 image data and save it as an image file
        // const productImagePath = `path/to/save/${productName}.png`; // Adjust path as needed

        // fs.writeFileSync(productImagePath, imageBuffer);

        // Create and save the product associated with the user
        const product = new Product({
            productName,
            price,
            description,
            status,
            category,
            userId: user._id,
            productImage: {
                data: imageBuffer,
                contentType: 'image/png' // Assuming PNG format
            }
        });
        await product.save();

        // Add the product to the user's product list
        user.productList.push(product._id); 
        await user.save();

        res.status(200).send('Product added successfully');
    } catch (error) {
        console.error('Error adding product:', error);
        res.status(500).send('Error adding product: ' + error.message);
    }
});


// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
