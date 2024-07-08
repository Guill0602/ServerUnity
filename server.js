const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB URI with SSL/TLS configuration
const MONGODB_URI = 'mongodb+srv://guillsango:gu6FoXUc5xUJe72m@streaming.m5diqrb.mongodb.net/EcommerceApp';

// Setup MongoDB session store
const store = new MongoDBStore({
    uri: MONGODB_URI,
    collection: 'sessions' // Collection name for sessions
});

store.on('error', function(error) {
    console.error('Session store error:', error);
});

// Express session middleware
app.use(session({
    secret: process.env.SECRET_KEY || 'your_secret_key',
    resave: false,
    saveUninitialized: false,
    store: store // Use MongoDBStore for session storage
}));

// Middleware setup
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: true }));
app.use(cors());

// Connect to MongoDB
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true, // Deprecated but harmless in older versions
    useUnifiedTopology: true // Deprecated but harmless in older versions
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('Failed to connect to MongoDB', err);
});

// Define MongoDB schemas and models (add your own as needed)
const idNumberSchema = new mongoose.Schema({
    id_number: String
});
const IdNumber = mongoose.model('IdNumber', idNumberSchema);

const userSchema = new mongoose.Schema({
    email: { type: String, unique: true },
    password: String,
    id_number: String,
    productList: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
    }],
    cart: [{
        cartId: { type: String, required: true }, // Store cartId as String
        product: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Product'
        }
    }],
    checkout: [{
        cartId: { type: String, required: true },
        product: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Product'
        }
    }]
});


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

const productSchema = new mongoose.Schema({
    productName: String,
    price: Number,
    description: String,
    status: {
        type: String,
        enum: ['New', 'Used']
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
    },
    reports: [{
        reason: String,
        reportedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }
    }]
});

const Product = mongoose.model('Product', productSchema);


app.post('/checkout', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.session.userId;

    try {
        const user = await User.findById(userId).populate('cart.product');
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Move all cart items to checkout
        user.checkout = user.cart;
        user.cart = [];

        await user.save();

        res.status(200).send('Checkout successful');
    } catch (error) {
        console.error('Error checking out:', error);
        res.status(500).send('Error checking out');
    }
});

// Endpoint to fetch checkout items for a user
app.get('/checkout', async (req, res) => {
    try {
        const userId = req.session.userId; // Assuming you have session middleware
        if (!userId) {
            return res.status(401).send('Unauthorized');
        }

        const user = await User.findById(userId).populate('checkout.product');
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Extract checkout items with product details
        const checkoutItems = user.checkout.map(item => ({
            _id: item.product._id.toString(),
            productName: item.product.productName,
            price: item.product.price,
            description: item.product.description,
            status: item.product.status,
            category: item.product.category,
            productImage: item.product.productImage.data.toString('base64'), // Assuming this is base64 encoded image
        }));

        res.status(200).json({ checkoutItems });
    } catch (error) {
        console.error('Error fetching checkout:', error);
        res.status(500).send('Error fetching checkout: ' + error.message);
    }
});



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
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user: ' + error.message);
    }
});

app.post('/login', async (req, res) => {
    const { identifier, password } = req.body;

    try {
        const user = await User.findOne({ $or: [{ email: identifier }, { id_number: identifier }] });

        if (!user) {
            return res.status(400).send('Invalid identifier or password');
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(400).send('Invalid identifier or password');
        }

        req.session.userId = user._id;

        res.json({ userId: user._id, message: 'Login successful' });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).send('Error logging in user');
    }
});

app.get('/adminLogin', async (req, res) => {
    const { email, password } = req.query;

    try {
        const admin = await Admin.findOne({ email });

        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        const passwordMatch = (admin.password === password);

        if (!passwordMatch) {
            return res.status(400).send('Invalid password');
        }

        res.json({ adminId: admin._id, message: 'Admin login successful' });
    } catch (error) {
        console.error('Error logging in admin:', error);
        res.status(500).send('Error logging in admin');
    }
});

// Get all users
app.get('/get-all-users', async (req, res) => {
    try {
        const users = await User.find().select('email id_number');
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Error fetching users');
    }
});

// Edit user details
app.put('/edit-user/:userId', async (req, res) => {
    const userId = req.params.userId;
    const { email, id_number } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        user.email = email || user.email;
        user.id_number = id_number || user.id_number;

        await user.save();
        res.status(200).send('User updated successfully');
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).send('Error updating user');
    }
});

// Delete a user
app.delete('/delete-user/:userId', async (req, res) => {
    const userId = req.params.userId;

    try {
        await User.findByIdAndDelete(userId);
        res.status(200).send('User deleted successfully');
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).send('Error deleting user');
    }
});

app.get('/get-user-profile', async (req, res) => {
    const userId = req.query.userId;

    try {
        const user = await User.findById(userId)
            .select('email id_number productList')
            .populate('productList');

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
                productImage: product.productImage.data.toString('base64')
            }))
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).send('Error fetching user profile');
    }
});

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
            productImage: product.productImage.data.toString('base64'),
            // Include the following line to indicate the productId
            productId: product._id
        });
    } catch (error) {
        console.error('Error fetching product details:', error);
        res.status(500).send('Error fetching product details');
    }
});

app.post('/add-to-cart', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.session.userId;
    const { productId, cartId } = req.body; // Ensure cartId is passed from Unity

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).send('Product not found');
        }

        // Push the product with cartId as a string
        user.cart.push({ cartId, product: product._id });
        await user.save();

        res.status(200).send('Product added to cart successfully');
    } catch (error) {
        console.error('Error adding product to cart:', error);
        res.status(500).send('Error adding product to cart: ' + error.message);
    }
});

// Endpoint to fetch cart items for a user
app.get('/get-cart', async (req, res) => {
    try {
        const userId = req.session.userId; // Assuming you have session middleware
        if (!userId) {
            return res.status(401).send('Unauthorized');
        }

        const user = await User.findById(userId).populate('cart.product');
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Extract cart items with product details
        const cartItems = user.cart.map(item => ({
            _id: item.product._id.toString(),
            productName: item.product.productName,
            price: item.product.price,
            description: item.product.description,
            status: item.product.status,
            category: item.product.category,
            productImage: item.product.productImage.data.toString('base64'), // Assuming this is base64 encoded image
        }));

        res.status(200).json({ cartItems });
    } catch (error) {
        console.error('Error fetching cart:', error);
        res.status(500).send('Error fetching cart: ' + error.message);
    }
});

app.get('/get-all-products', async (req, res) => {
    try {
        const products = await Product.find().populate('userId', 'email');

        const formattedProducts = products.map(product => ({
            _id: product._id,
            productName: product.productName,
            price: product.price,
            description: product.description,
            status: product.status,
            category: product.category,
            productImage: product.productImage.data.toString('base64'),
            userId: product.userId._id,
            userEmail: product.userId.email
        }));

        res.json(formattedProducts);
    } catch (error) {
        console.error('Error fetching all products:', error);
        res.status(500).send('Error fetching all products');
    }
});

app.post('/report-product', async (req, res) => {
    const { productId, reason } = req.body;
    const reportedBy = req.session.userId; // Assuming user is logged in and session is managed

    try {
        const product = await Product.findById(productId);

        if (!product) {
            return res.status(404).send('Product not found');
        }

        // Check if the user has already reported this product
        const alreadyReported = product.reports.some(report => report.reportedBy.equals(reportedBy));

        if (alreadyReported) {
            return res.status(400).send('You have already reported this product');
        }

        // Add the report to the product
        product.reports.push({ reason, reportedBy });
        await product.save();

        // Notify the user who posted the product (if needed)

        res.status(200).send('Product reported successfully');
    } catch (error) {
        console.error('Error reporting product:', error);
        res.status(500).send('Error reporting product');
    }
});

app.get('/get-all-reports', async (req, res) => {
    try {
        // Find all products with populated userId and include only products with reports
        const products = await Product.find({ reports: { $exists: true, $not: { $size: 0 } } }).populate('userId', 'email');

        const allReports = products.reduce((allReports, product) => {
            product.reports.forEach(report => {
                allReports.push({
                    productId: product._id,
                    productName: product.productName,
                    reason: report.reason,
                    reportedBy: report.reportedBy,
                    userEmail: product.userId.email
                });
            });
            return allReports;
        }, []);

        res.json(allReports);
    } catch (error) {
        console.error('Error fetching all reports:', error);
        res.status(500).send('Error fetching all reports');
    }
});


app.post('/add-product', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.session.userId;

    try {
        const { productName, price, description, status, category, productImage } = req.body;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        const imageBuffer = Buffer.from(productImage, 'base64');

        const product = new Product({
            productName,
            price,
            description,
            status,
            category,
            userId: user._id,
            productImage: {
                data: imageBuffer,
                contentType: 'image/png'
            }
        });
        await product.save();

        user.productList.push(product._id);
        await user.save();

        res.status(200).send('Product added successfully');
    } catch (error) {
        console.error('Error adding product:', error);
        res.status(500).send('Error adding product: ' + error.message);
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});