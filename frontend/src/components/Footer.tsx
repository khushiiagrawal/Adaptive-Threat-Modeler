import { motion } from "framer-motion";

const footerSections = {
  services: [
    "Threat Detection",
    "Penetration Testing",
    "Compliance Assessment",
    "Security Architecture",
  ],
  explore: ["About Us", "Case Studies", "Resources", "Blog"],
  connect: ["Contact", "Support", "Careers", "Partners"],
};

export function Footer() {
  return (
    <footer className="relative border-t border-primary/20 bg-cyber-darker">
      <div className="container mx-auto px-6 py-16">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-12">
          {/* Brand */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
          >
            <div className="text-3xl font-bold cyber-text-glow mb-6">
              Adaptive Threat Modeler
            </div>
            <p className="text-foreground/70 text-sm leading-relaxed">
              Continuous, AI-powered threat modeling that keeps pace with your
              code and cloud.
            </p>
          </motion.div>

          {/* Services */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            viewport={{ once: true }}
          >
            <h3 className="text-primary font-semibold mb-6 tracking-wider">
              PRODUCT
            </h3>
            <ul className="space-y-3">
              {footerSections.services.map((item) => (
                <li key={item}>
                  <a
                    href="#"
                    className="text-foreground/70 hover:text-primary transition-colors duration-300 text-sm"
                  >
                    {item}
                  </a>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Explore */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            viewport={{ once: true }}
          >
            <h3 className="text-primary font-semibold mb-6 tracking-wider">
              EXPLORE
            </h3>
            <ul className="space-y-3">
              {footerSections.explore.map((item) => (
                <li key={item}>
                  <a
                    href="#"
                    className="text-foreground/70 hover:text-primary transition-colors duration-300 text-sm"
                  >
                    {item}
                  </a>
                </li>
              ))}
            </ul>
          </motion.div>

          {/* Connect */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            viewport={{ once: true }}
          >
            <h3 className="text-primary font-semibold mb-6 tracking-wider">
              CONNECT
            </h3>
            <ul className="space-y-3">
              {footerSections.connect.map((item) => (
                <li key={item}>
                  <a
                    href="#"
                    className="text-foreground/70 hover:text-primary transition-colors duration-300 text-sm"
                  >
                    {item}
                  </a>
                </li>
              ))}
            </ul>
          </motion.div>
        </div>

        {/* Bottom section */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          viewport={{ once: true }}
          className="border-t border-primary/10 pt-8 mt-16"
        >
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="text-foreground/50 text-sm">
              © {new Date().getFullYear()} DOTDNA. All rights reserved.
            </div>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <a
                href="#"
                className="text-foreground/50 hover:text-primary transition-colors text-sm"
              >
                Privacy Policy
              </a>
              <a
                href="#"
                className="text-foreground/50 hover:text-primary transition-colors text-sm"
              >
                Terms of Service
              </a>
            </div>
          </div>
        </motion.div>
      </div>
    </footer>
  );
}
