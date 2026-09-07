const express=require('express'),cors=require('cors'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),path=require('path'),crypto=require('crypto'),helmet=require('helmet'),rateLimit=require('express-rate-limit');
const {Pool}=require('pg');
const app=express(),PORT=process.env.PORT||3000;

// --- Base de données : PostgreSQL (Neon) au lieu de SQLite, pour que les données survivent aux redéploiements/mises en veille du plan gratuit Render. ---
if(!process.env.DATABASE_URL)console.warn('⚠️  DATABASE_URL non défini : la base de données ne pourra pas se connecter. Ajoute la chaîne de connexion Neon dans les variables d\'environnement Render.');
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:{rejectUnauthorized:false}});

// Petits adaptateurs qui gardent une écriture proche de l'ancien code SQLite : les requêtes utilisent toujours "?" comme avant,
// converti automatiquement en $1,$2... pour PostgreSQL. Toutes les fonctions deviennent asynchrones (await) car PostgreSQL fonctionne par le réseau.
function pgize(sql){let i=0;return sql.replace(/\?/g,()=>'$'+(++i))}
async function get(sql,...params){const r=await pool.query(pgize(sql),params);return r.rows[0]}
async function all(sql,...params){const r=await pool.query(pgize(sql),params);return r.rows}
async function run(sql,...params){const r=await pool.query(pgize(sql),params);return r}

const SECRET=process.env.JWT_SECRET||crypto.randomBytes(32).toString('hex');
if(!process.env.JWT_SECRET)console.warn('⚠️  JWT_SECRET non défini : un secret temporaire a été généré. Ajoute JWT_SECRET dans les variables d\'environnement Render pour éviter les déconnexions au redémarrage.');
app.use(helmet({contentSecurityPolicy:false}));
const authLimiter=rateLimit({windowMs:15*60*1000,max:20,standardHeaders:true,legacyHeaders:false,message:{message:'Trop de tentatives. Réessaie dans quelques minutes.'}});

async function createSchema(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('buyer','seller','admin')),created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS shops(id SERIAL PRIMARY KEY,user_id INTEGER UNIQUE NOT NULL,name TEXT NOT NULL,description TEXT DEFAULT '',phone TEXT DEFAULT '',premium INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS products(id SERIAL PRIMARY KEY,seller_id INTEGER NOT NULL,shop_name TEXT NOT NULL,name TEXT NOT NULL,category TEXT NOT NULL,price INTEGER NOT NULL,stock INTEGER NOT NULL,icon TEXT DEFAULT '📦',image TEXT DEFAULT '',description TEXT DEFAULT '',active INTEGER DEFAULT 1,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS orders(id SERIAL PRIMARY KEY,user_id INTEGER NOT NULL,total INTEGER NOT NULL,status TEXT DEFAULT 'pending',address TEXT NOT NULL,city TEXT NOT NULL,phone TEXT DEFAULT '',note TEXT DEFAULT '',payment_method TEXT DEFAULT 'cash',payment_reference TEXT DEFAULT '',payment_status TEXT DEFAULT 'unpaid',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS order_items(id SERIAL PRIMARY KEY,order_id INTEGER,product_id INTEGER,product_name TEXT,price INTEGER,qty INTEGER,seller_id INTEGER);
    CREATE TABLE IF NOT EXISTS favorites(id SERIAL PRIMARY KEY,user_id INTEGER NOT NULL,product_id INTEGER NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id,product_id));
    CREATE TABLE IF NOT EXISTS reviews(id SERIAL PRIMARY KEY,user_id INTEGER NOT NULL,product_id INTEGER NOT NULL,rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),comment TEXT DEFAULT '',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id,product_id));
    CREATE TABLE IF NOT EXISTS notifications(id SERIAL PRIMARY KEY,user_id INTEGER NOT NULL,title TEXT NOT NULL,message TEXT NOT NULL,read INTEGER DEFAULT 0,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS newsletter(id SERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
  `);
  // Ajouts progressifs sûrs même si les tables existaient déjà (équivalent des anciennes migrations SQLite, en plus simple grâce à IF NOT EXISTS).
  await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS image TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT DEFAULT 'cash'`);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_reference TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'unpaid'`);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE shops ADD COLUMN IF NOT EXISTS phone TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE shops ADD COLUMN IF NOT EXISTS premium INTEGER DEFAULT 0`);
}

const PAYMENT_INFO={merchant:process.env.MERCHANT_NAME||'Madazon',mvola:process.env.MVOLA_NUMBER||'',orange:process.env.ORANGE_NUMBER||'',airtel:process.env.AIRTEL_NUMBER||''};
const ADMIN_EMAIL=(process.env.ADMIN_EMAIL||'').trim().toLowerCase();

app.use(cors());app.use(express.json({limit:'1mb'}));
const pub=u=>({id:u.id,name:u.name,email:u.email,role:u.role}),tok=u=>jwt.sign(pub(u),SECRET,{expiresIn:'7d'});
function auth(req,res,next){try{let h=req.headers.authorization||'';if(!h.startsWith('Bearer '))throw Error();req.user=jwt.verify(h.slice(7),SECRET);next()}catch(e){res.status(401).json({message:'Authentification requise.'})}}
function role(r){return(req,res,next)=>req.user.role===r?next():res.status(403).json({message:'Accès refusé.'})}
async function notify(userId,title,message){await run('INSERT INTO notifications(user_id,title,message) VALUES(?,?,?)',userId,title,message)}

app.get('/api/health',(q,s)=>s.json({ok:true,version:'9'}));
app.get('/api/payment-info',(q,s)=>s.json(PAYMENT_INFO));
app.get('/api/reviews/featured',async(q,s)=>{try{s.json({reviews:await all("SELECT r.rating,r.comment,r.created_at,u.name,p.name product_name FROM reviews r JOIN users u ON u.id=r.user_id JOIN products p ON p.id=r.product_id WHERE r.rating>=4 AND length(trim(r.comment))>0 ORDER BY r.id DESC LIMIT 6")})}catch(e){s.status(500).json({message:e.message})}});
app.post('/api/newsletter',async(q,s)=>{let email=String(q.body?.email||'').trim().toLowerCase();if(!/^\S+@\S+\.\S+$/.test(email))return s.status(400).json({message:'E-mail invalide.'});try{await run('INSERT INTO newsletter(email) VALUES(?) ON CONFLICT (email) DO NOTHING',email)}catch(e){}s.json({ok:true})});
app.post('/api/auth/register',authLimiter,async(req,res)=>{let{name,email,password,role='buyer'}=req.body||{};if(!name||!email||!password||password.length<6||!['buyer','seller'].includes(role))return res.status(400).json({message:'Données invalides.'});let cleanEmail=email.trim().toLowerCase();if(ADMIN_EMAIL&&cleanEmail===ADMIN_EMAIL)role='admin';try{let u=await get('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?) RETURNING *',name.trim(),cleanEmail,await bcrypt.hash(password,12),role);res.status(201).json({token:tok(u),user:pub(u)})}catch(e){res.status(409).json({message:'Cet e-mail est déjà utilisé.'})}});
app.post('/api/auth/login',authLimiter,async(req,res)=>{let u=await get('SELECT * FROM users WHERE email=?',String(req.body.email||'').trim().toLowerCase());if(!u||!(await bcrypt.compare(req.body.password||'',u.password_hash)))return res.status(401).json({message:'Identifiants incorrects.'});res.json({token:tok(u),user:pub(u)})});
app.get('/api/me',auth,async(q,s)=>s.json({user:await get('SELECT id,name,email,role,created_at FROM users WHERE id=?',q.user.id)}));
app.patch('/api/me',auth,async(q,s)=>{let{name}=q.body||{};if(!name||name.trim().length<2)return s.status(400).json({message:'Nom invalide.'});await run('UPDATE users SET name=? WHERE id=?',name.trim(),q.user.id);s.json({user:await get('SELECT id,name,email,role,created_at FROM users WHERE id=?',q.user.id)})});
app.get('/api/categories',async(q,s)=>s.json({categories:(await all('SELECT category,COUNT(*) count FROM products WHERE active=1 GROUP BY category ORDER BY category')).map(c=>({category:c.category,count:+c.count}))}));
app.get('/api/products',async(q,s)=>{let{q:term,category,min,max,sort='newest'}=q.query,sql='SELECT p.id,p.seller_id,p.shop_name seller,p.name,p.category,p.price,p.stock,p.icon,p.image,p.description,p.created_at,COALESCE(sh.premium,0) premium,COALESCE(ROUND(AVG(r.rating),1),0) rating,COUNT(r.id) reviews FROM products p LEFT JOIN reviews r ON r.product_id=p.id LEFT JOIN shops sh ON sh.user_id=p.seller_id WHERE p.active=1',a=[];if(term){sql+=" AND lower(p.name||' '||p.description||' '||p.category) LIKE ?";a.push('%'+String(term).toLowerCase()+'%')}if(category&&category!=='Toutes'){sql+=' AND p.category=?';a.push(category)}if(Number.isFinite(+min)){sql+=' AND p.price>=?';a.push(+min)}if(Number.isFinite(+max)){sql+=' AND p.price<=?';a.push(+max)}sql+=' GROUP BY p.id,sh.premium ORDER BY premium DESC, '+(sort==='price_asc'?'p.price ASC':sort==='price_desc'?'p.price DESC':sort==='rating'?'rating DESC':'p.id DESC');try{let rows=await all(sql,...a);s.json({products:rows.map(p=>({...p,rating:+p.rating,reviews:+p.reviews,premium:+p.premium}))})}catch(e){s.status(500).json({message:e.message})}});
app.get('/api/products/:id',async(req,res)=>{try{let p=await get('SELECT p.*,COALESCE(sh.premium,0) premium,COALESCE(ROUND(AVG(r.rating),1),0) rating,COUNT(r.id) reviews FROM products p LEFT JOIN reviews r ON r.product_id=p.id LEFT JOIN shops sh ON sh.user_id=p.seller_id WHERE p.id=? AND p.active=1 GROUP BY p.id,sh.premium',+req.params.id);if(!p)return res.status(404).json({message:'Produit introuvable.'});p.rating=+p.rating;p.reviews=+p.reviews;p.premium=+p.premium;res.json({product:p,reviews:await all('SELECT r.rating,r.comment,r.created_at,u.name FROM reviews r JOIN users u ON u.id=r.user_id WHERE r.product_id=? ORDER BY r.id DESC',p.id)})}catch(e){res.status(500).json({message:e.message})}});
app.get('/api/favorites',auth,async(q,s)=>s.json({favorites:(await all('SELECT product_id FROM favorites WHERE user_id=?',q.user.id)).map(x=>x.product_id)}));
app.post('/api/favorites/:id',auth,async(q,s)=>{let p=await get('SELECT id FROM products WHERE id=? AND active=1',+q.params.id);if(!p)return s.status(404).json({message:'Produit introuvable.'});let f=await get('SELECT id FROM favorites WHERE user_id=? AND product_id=?',q.user.id,p.id);if(f)await run('DELETE FROM favorites WHERE id=?',f.id);else await run('INSERT INTO favorites(user_id,product_id) VALUES(?,?)',q.user.id,p.id);s.json({favorite:!f})});
app.post('/api/products/:id/reviews',auth,async(q,s)=>{let{rating,comment=''}=q.body||{};if(!Number.isInteger(+rating)||+rating<1||+rating>5)return s.status(400).json({message:'Note de 1 à 5 requise.'});let p=await get('SELECT id FROM products WHERE id=? AND active=1',+q.params.id);if(!p)return s.status(404).json({message:'Produit introuvable.'});let bought=await get('SELECT 1 FROM order_items i JOIN orders o ON o.id=i.order_id WHERE i.product_id=? AND o.user_id=? LIMIT 1',p.id,q.user.id);if(!bought)return s.status(403).json({message:'Vous devez avoir acheté ce produit pour laisser un avis.'});await run(`INSERT INTO reviews(user_id,product_id,rating,comment) VALUES(?,?,?,?) ON CONFLICT(user_id,product_id) DO UPDATE SET rating=excluded.rating,comment=excluded.comment`,q.user.id,p.id,+rating,String(comment).slice(0,500));s.json({ok:true})});
app.get('/api/notifications',auth,async(q,s)=>s.json({notifications:await all('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 30',q.user.id)}));
app.patch('/api/notifications/read',auth,async(q,s)=>{await run('UPDATE notifications SET read=1 WHERE user_id=?',q.user.id);s.json({ok:true})});
app.get('/api/seller/shop',auth,role('seller'),async(q,s)=>s.json({shop:(await get('SELECT * FROM shops WHERE user_id=?',q.user.id))||null}));
app.post('/api/seller/shop',auth,role('seller'),async(q,s)=>{let{name,description='',phone=''}=q.body;if(!name)return s.status(400).json({message:'Nom requis.'});let x=await get('SELECT id FROM shops WHERE user_id=?',q.user.id);if(x)await run('UPDATE shops SET name=?,description=?,phone=? WHERE user_id=?',name.trim(),description,String(phone).trim(),q.user.id);else await run('INSERT INTO shops(user_id,name,description,phone) VALUES(?,?,?,?)',q.user.id,name.trim(),description,String(phone).trim());await run('UPDATE products SET shop_name=? WHERE seller_id=?',name.trim(),q.user.id);s.json({ok:true})});
app.get('/api/seller/products',auth,role('seller'),async(q,s)=>s.json({products:await all('SELECT * FROM products WHERE seller_id=? AND active=1 ORDER BY id DESC',q.user.id)}));
app.get('/api/seller/stats',auth,role('seller'),async(q,s)=>{let id=q.user.id;let sales=await get("SELECT COALESCE(SUM(i.price*i.qty),0) revenue,COUNT(DISTINCT i.order_id) orders FROM order_items i JOIN orders o ON o.id=i.order_id WHERE i.seller_id=? AND o.status!='cancelled'",id);let products=await get('SELECT COUNT(*) n FROM products WHERE seller_id=? AND active=1',id);let rating=await get('SELECT COALESCE(ROUND(AVG(r.rating),1),0) rating,COUNT(r.id) reviews FROM reviews r JOIN products p ON p.id=r.product_id WHERE p.seller_id=?',id);let top=await get('SELECT p.name,SUM(i.qty) sold FROM order_items i JOIN products p ON p.id=i.product_id WHERE i.seller_id=? GROUP BY i.product_id,p.name ORDER BY sold DESC LIMIT 1',id);let pending=await get("SELECT COUNT(DISTINCT i.order_id) n FROM order_items i JOIN orders o ON o.id=i.order_id WHERE i.seller_id=? AND o.status IN ('pending','confirmed')",id);let premium=await get('SELECT premium FROM shops WHERE user_id=?',id);s.json({revenue:+sales.revenue,orders:+sales.orders,products:+products.n,rating:+rating.rating,reviews:+rating.reviews,topProduct:top?top.name:null,topProductSold:top?+top.sold:0,pendingOrders:+pending.n,premium:premium?!!premium.premium:false})});
app.post('/api/seller/products',auth,role('seller'),async(q,s)=>{let{name,category,price,stock,icon='📦',image='',description=''}=q.body,shop=await get('SELECT name FROM shops WHERE user_id=?',q.user.id);if(!shop)return s.status(400).json({message:'Créez votre boutique d’abord.'});if(!name||!category||!Number.isInteger(+price)||+price<0||!Number.isInteger(+stock)||+stock<0)return s.status(400).json({message:'Données produit invalides.'});let x=await get('INSERT INTO products(seller_id,shop_name,name,category,price,stock,icon,image,description) VALUES(?,?,?,?,?,?,?,?,?) RETURNING id',q.user.id,shop.name,name.trim(),category,+price,+stock,icon||'📦',String(image||'').trim(),description||'');s.status(201).json({id:x.id})});
app.patch('/api/seller/products/:id',auth,role('seller'),async(q,s)=>{let{name,category,price,stock,icon,image,description}=q.body||{};if(!name||!category||!Number.isInteger(+price)||+price<0||!Number.isInteger(+stock)||+stock<0)return s.status(400).json({message:'Données invalides.'});let x=await run('UPDATE products SET name=?,category=?,price=?,stock=?,icon=?,image=?,description=? WHERE id=? AND seller_id=? AND active=1',name.trim(),category,+price,+stock,icon||'📦',String(image||'').trim(),description||'',+q.params.id,q.user.id);if(!x.rowCount)return s.status(404).json({message:'Produit introuvable.'});s.json({ok:true})});
app.delete('/api/seller/products/:id',auth,role('seller'),async(q,s)=>{await run('UPDATE products SET active=0 WHERE id=? AND seller_id=?',+q.params.id,q.user.id);s.json({ok:true})});
app.post('/api/orders',auth,async(q,s)=>{
  let{items,address,city,phone,note='',payment_method='cash',payment_reference=''}=q.body||{};
  if(!items?.length||!address||!city||!phone)return s.status(400).json({message:'Panier, adresse et téléphone requis.'});
  let methods=['cash','mvola','orange','airtel'];
  if(!methods.includes(payment_method))return s.status(400).json({message:'Mode de paiement invalide.'});
  if(payment_method!=='cash'&&!String(payment_reference).trim())return s.status(400).json({message:'Référence de transaction requise pour un paiement Mobile Money.'});
  const client=await pool.connect();
  try{
    await client.query('BEGIN');
    let total=0,rows=[];
    for(let i of items){
      let pr=await client.query('SELECT * FROM products WHERE id=$1 AND active=1',[+i.id]),p=pr.rows[0],qty=+i.qty;
      if(!p||!Number.isInteger(qty)||qty<1||qty>p.stock)throw Error('Stock insuffisant ou produit invalide.');
      total+=p.price*qty;rows.push([p,qty]);
    }
    let pStatus=payment_method==='cash'?'unpaid':'pending';
    let oi=await client.query('INSERT INTO orders(user_id,total,status,address,city,phone,note,payment_method,payment_reference,payment_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id',[q.user.id,total,'pending',address,city,String(phone).trim(),note,payment_method,String(payment_reference).trim(),pStatus]);
    let orderId=oi.rows[0].id;
    for(let [p,qty] of rows){
      await client.query('UPDATE products SET stock=stock-$1 WHERE id=$2',[qty,p.id]);
      await client.query('INSERT INTO order_items(order_id,product_id,product_name,price,qty,seller_id) VALUES($1,$2,$3,$4,$5,$6)',[orderId,p.id,p.name,p.price,qty,p.seller_id]);
      await client.query('INSERT INTO notifications(user_id,title,message) VALUES($1,$2,$3)',[p.seller_id,'Nouvelle commande','Une commande contient votre produit « '+p.name+' ».']);
    }
    await client.query('INSERT INTO notifications(user_id,title,message) VALUES($1,$2,$3)',[q.user.id,'Commande créée','Votre commande #'+orderId+' est en attente.']);
    await client.query('COMMIT');
    const order=await get('SELECT * FROM orders WHERE id=?',orderId);
    s.status(201).json({order});
  }catch(e){
    await client.query('ROLLBACK');
    s.status(400).json({message:e.message});
  }finally{
    client.release();
  }
});
app.get('/api/orders',auth,async(q,s)=>s.json({orders:await all('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC',q.user.id)}));
app.get('/api/orders/:id',auth,async(q,s)=>{let o=await get('SELECT * FROM orders WHERE id=? AND user_id=?',+q.params.id,q.user.id);if(!o)return s.status(404).json({message:'Commande introuvable.'});s.json({order:o,items:await all('SELECT i.*,sh.phone seller_phone FROM order_items i LEFT JOIN shops sh ON sh.user_id=i.seller_id WHERE i.order_id=?',o.id)})});
app.get('/api/seller/orders',auth,role('seller'),async(q,s)=>s.json({orders:await all('SELECT o.* FROM orders o JOIN order_items i ON i.order_id=o.id WHERE i.seller_id=? GROUP BY o.id ORDER BY o.id DESC',q.user.id)}));
app.patch('/api/seller/orders/:id',auth,role('seller'),async(q,s)=>{let a=['pending','confirmed','shipped','delivered','cancelled'];if(!a.includes(q.body.status))return s.status(400).json({message:'Statut invalide.'});let x=await get('SELECT o.user_id FROM orders o JOIN order_items i ON i.order_id=o.id WHERE o.id=? AND i.seller_id=?',+q.params.id,q.user.id);if(!x)return s.status(404).json({message:'Commande introuvable.'});await run('UPDATE orders SET status=? WHERE id=?',q.body.status,+q.params.id);await notify(x.user_id,'Commande mise à jour','La commande #'+q.params.id+' est maintenant « '+q.body.status+' ».');s.json({ok:true})});
app.patch('/api/admin/orders/:id/payment',auth,role('admin'),async(q,s)=>{let a=['unpaid','pending','paid'];if(!a.includes(q.body.payment_status))return s.status(400).json({message:'Statut de paiement invalide.'});let o=await get('SELECT user_id FROM orders WHERE id=?',+q.params.id);if(!o)return s.status(404).json({message:'Commande introuvable.'});await run('UPDATE orders SET payment_status=? WHERE id=?',q.body.payment_status,+q.params.id);if(q.body.payment_status==='paid')await notify(o.user_id,'Paiement confirmé','Le paiement de votre commande #'+q.params.id+' a été reçu.');s.json({ok:true})});
app.get('/api/admin/shops',auth,role('admin'),async(q,s)=>s.json({shops:await all('SELECT sh.id,sh.user_id,sh.name,sh.premium,u.name owner,u.email FROM shops sh JOIN users u ON u.id=sh.user_id ORDER BY sh.id DESC')}));
app.patch('/api/admin/shops/:id/premium',auth,role('admin'),async(q,s)=>{let x=await run('UPDATE shops SET premium=? WHERE id=?',q.body.premium?1:0,+q.params.id);if(!x.rowCount)return s.status(404).json({message:'Boutique introuvable.'});let sh=await get('SELECT user_id,name FROM shops WHERE id=?',+q.params.id);await notify(sh.user_id,q.body.premium?'Boutique Premium activée':'Boutique Premium désactivée',q.body.premium?'Votre boutique « '+sh.name+' » est maintenant mise en avant sur Madazon.':'Le statut Premium de votre boutique a été retiré.');s.json({ok:true})});
app.get('/api/admin/overview',auth,role('admin'),async(q,s)=>{let users=await get('SELECT count(*) n FROM users'),sellers=await get("SELECT count(*) n FROM users WHERE role='seller'"),products=await get('SELECT count(*) n FROM products WHERE active=1'),orders=await get('SELECT count(*) n FROM orders');s.json({stats:{users:+users.n,sellers:+sellers.n,products:+products.n,orders:+orders.n},orders:await all('SELECT o.*,u.name customer_name FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 30')})});

app.use(express.static(path.join(__dirname,'..')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'..','index.html')));

(async()=>{
  try{
    await createSchema();
    if(ADMIN_EMAIL)await run("UPDATE users SET role='admin' WHERE lower(email)=?",ADMIN_EMAIL);
    app.listen(PORT,'0.0.0.0',()=>console.log('Madazon V9 (PostgreSQL): http://0.0.0.0:'+PORT));
  }catch(e){
    console.error('❌ Erreur au démarrage (vérifie DATABASE_URL) :',e.message);
    process.exit(1);
  }
})();
